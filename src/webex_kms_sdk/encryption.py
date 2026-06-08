from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jwcrypto import jwe  # type: ignore[import-untyped]
from jwcrypto import jwk as jose_jwk  # type: ignore[import-untyped]

from .config import Config
from .core import CoreHTTPClient
from .errors import KMSProtocolError, api_error_from_response
from .models import JWK, Key, KMSMessage

KMS_URI_PREFIX = "kms://"
ECDH_TTL_SECONDS = 60 * 60
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

log = logging.getLogger(__name__)


@dataclass(slots=True)
class KMSInfo:
    """KMS cluster metadata and wrapping key material for a user."""

    kms_cluster: str
    rsa_public_key: Any


@dataclass(slots=True)
class ECDHContext:
    """Cached ECDH session state used to wrap and unwrap KMS messages."""

    local_private_key: ec.EllipticCurvePrivateKey
    shared_secret: bytes
    ecdh_key_uri: str
    kms_cluster: str
    created_at: float


@dataclass(slots=True)
class PendingKMSRequest:
    """Outstanding asynchronous KMS request waiting for Mercury delivery."""

    future: asyncio.Future[bytes]
    ecdh_private_key: ec.EllipticCurvePrivateKey | None = None


class EncryptionClient:
    """Client for KMS key retrieval, response processing, and content decryption."""

    def __init__(self, core: CoreHTTPClient, config: Config) -> None:
        """Create an encryption client.

        :param core: Shared HTTP client used for Webex and KMS requests.
        :param config: Runtime configuration for KMS endpoints, timeouts, and cache behavior.
        :returns: None.
        """
        log.debug("EncryptionClient.__init__: initialize encryption client")
        self._core = core
        self._config = config
        self._key_cache: dict[str, Key] = {}
        self._key_cache_lock = asyncio.Lock()
        self._inflight_keys: dict[str, asyncio.Task[Key]] = {}
        self._inflight_lock = asyncio.Lock()
        self._pending_requests: dict[str, PendingKMSRequest] = {}
        self._pending_lock = asyncio.Lock()
        self._ecdh_context: ECDHContext | None = None
        self._ecdh_lock = asyncio.Lock()
        self._device_url = ""
        self._user_id = ""

    def set_device_info(self, device_url: str, user_id: str) -> None:
        """Set device identity used in outbound KMS requests.

        :param device_url: WDM device URL to use as the KMS client identifier.
        :param user_id: Webex user ID associated with the device.
        :returns: None.
        """
        log.debug(
            "EncryptionClient.set_device_info: set KMS device info device_url=%s user_id_present=%s",
            device_url,
            bool(user_id),
        )
        self._device_url = device_url
        self._user_id = user_id

    async def get_key(self, key_uri: str) -> Key:
        """Retrieve a KMS key by URI with caching and inflight coalescing.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        # Serve cached keys first when cache use is enabled.
        log.debug("EncryptionClient.get_key: retrieve key key_uri=%s", key_uri)
        if not self._config.disable_key_cache:
            async with self._key_cache_lock:
                cached = self._key_cache.get(key_uri)
            if cached is not None:
                log.debug("EncryptionClient.get_key: cache hit key_uri=%s", key_uri)
                return cached

        # Validate the URI before creating or joining an inflight retrieval task.
        log.debug("EncryptionClient.get_key: validate KMS URI key_uri=%s", key_uri)
        parse_kms_uri(key_uri)
        async with self._inflight_lock:
            task = self._inflight_keys.get(key_uri)
            if task is None:
                log.debug("EncryptionClient.get_key: create inflight retrieval task key_uri=%s", key_uri)
                task = asyncio.create_task(self._retrieve_and_cache_key(key_uri))
                self._inflight_keys[key_uri] = task
            else:
                log.debug("EncryptionClient.get_key: join inflight retrieval task key_uri=%s", key_uri)

        try:
            return await task
        finally:
            # Clear the coalescing entry once the shared task has finished.
            if task.done():
                async with self._inflight_lock:
                    if self._inflight_keys.get(key_uri) is task:
                        log.debug(
                            "EncryptionClient.get_key: clear inflight retrieval task key_uri=%s",
                            key_uri,
                        )
                        self._inflight_keys.pop(key_uri, None)

    def cache_key(self, key: Key | None) -> None:
        """Store a KMS key in the local cache when it has a URI.

        :param key: Optional key to cache.
        :returns: None.
        """
        if key is None or not key.uri:
            log.debug("EncryptionClient.cache_key: skip empty key")
            return
        log.debug("EncryptionClient.cache_key: cache KMS key uri=%s kid=%s", key.uri, key.jwk.kid)
        self._key_cache[key.uri] = key

    def process_kms_messages(self, jwe_strings: list[str]) -> None:
        """Process KMS response messages received over Mercury.

        :param jwe_strings: Raw KMS messages, usually compact JWE strings.
        :returns: None.
        """
        # Snapshot current ECDH state and pending exchange keys for decrypt attempts.
        log.debug(
            "EncryptionClient.process_kms_messages: process KMS messages count=%s",
            len(jwe_strings),
        )
        ecdh_context = self._ecdh_context
        pending_ecdh_keys = {
            request_id: req.ecdh_private_key
            for request_id, req in self._pending_requests.items()
            if req.ecdh_private_key is not None
        }

        for raw_message in jwe_strings:
            if not raw_message:
                continue

            plaintext: bytes | None = None
            message = raw_message

            # Some KMS payloads arrive as compact JWS-like envelopes with plaintext payloads.
            log.debug(
                "EncryptionClient.process_kms_messages: inspect KMS message dots=%s length=%s",
                message.count("."),
                len(message),
            )
            if message.count(".") == 2:
                parts = message.split(".", 2)
                try:
                    payload = _b64url_decode(parts[1])
                except ValueError:
                    payload = b""
                if payload.startswith(b"{"):
                    plaintext = payload
                elif payload:
                    message = payload.decode("utf-8", errors="ignore")

            # Decrypt compact JWE responses using the active or pending ECDH keys.
            if plaintext is None and message.count(".") == 4:
                if ecdh_context is not None:
                    try:
                        log.debug("EncryptionClient.process_kms_messages: decrypt with active ECDH context")
                        plaintext = unwrap_with_shared_secret(message, ecdh_context.shared_secret)
                    except Exception:
                        log.debug(
                            "EncryptionClient.process_kms_messages: active ECDH decrypt failed",
                            exc_info=True,
                        )
                        plaintext = None

                if plaintext is None:
                    for private_key in pending_ecdh_keys.values():
                        if private_key is None:
                            continue
                        try:
                            log.debug("EncryptionClient.process_kms_messages: decrypt with pending ECDH key")
                            plaintext = _decrypt_ecdh_jwe(message, private_key)
                            break
                        except Exception:
                            log.debug(
                                "EncryptionClient.process_kms_messages: pending ECDH decrypt failed",
                                exc_info=True,
                            )
                            continue

            # Plain JSON messages are accepted for tests and synchronous transport variants.
            if plaintext is None and message.startswith("{"):
                log.debug("EncryptionClient.process_kms_messages: use plaintext KMS JSON message")
                plaintext = message.encode("utf-8")

            if plaintext is None:
                log.debug("EncryptionClient.process_kms_messages: skip undecryptable KMS message")
                continue

            # Parse the KMS message and ignore malformed payloads.
            try:
                parsed = json.loads(plaintext)
            except json.JSONDecodeError:
                log.debug("EncryptionClient.process_kms_messages: skip invalid KMS JSON payload")
                continue
            if not isinstance(parsed, dict):
                log.debug("EncryptionClient.process_kms_messages: skip non-object KMS payload")
                continue
            kms_message = KMSMessage.from_dict(parsed)

            # Resolve pending asynchronous requests before caching broadcast keys.
            if kms_message.request_id:
                log.debug(
                    "EncryptionClient.process_kms_messages: match pending KMS request request_id=%s",
                    kms_message.request_id,
                )
                pending = self._pending_requests.pop(kms_message.request_id, None)
                if pending is not None and not pending.future.done():
                    pending.future.set_result(plaintext)
                    continue

            # Cache any key material included in unsolicited or synchronous responses.
            if kms_message.key is not None:
                self.cache_key(kms_message.key)
            for key in kms_message.keys:
                self.cache_key(key)

    async def decrypt_text(self, key_uri: str, ciphertext: str) -> str:
        """Decrypt UTF-8 text encrypted with a KMS-managed symmetric key.

        :param key_uri: KMS URI for the symmetric key.
        :param ciphertext: Compact JWE ciphertext.
        :returns: Decrypted UTF-8 plaintext.
        """
        if not key_uri:
            raise ValueError("key URI is required")
        if not ciphertext:
            raise ValueError("ciphertext is required")

        # Retrieve the symmetric key and unwrap the ciphertext payload.
        log.debug(
            "EncryptionClient.decrypt_text: decrypt text key_uri=%s ciphertext_length=%s",
            key_uri,
            len(ciphertext),
        )
        key = await self.get_key(key_uri)
        raw_key = key.jwk.symmetric_key()
        plaintext = unwrap_with_shared_secret(ciphertext, raw_key)
        log.debug("EncryptionClient.decrypt_text: decrypted text bytes=%s", len(plaintext))
        return plaintext.decode("utf-8")

    async def decrypt_message_content(self, encryption_key_url: str, encrypted_content: str) -> str:
        """Decrypt a Webex message content field.

        :param encryption_key_url: KMS key URI from the activity.
        :param encrypted_content: Encrypted display name/content value.
        :returns: Decrypted message content.
        """
        if not encryption_key_url:
            raise ValueError("encryption key URL is required")
        if not encrypted_content:
            raise ValueError("encrypted content is required")
        log.debug(
            "EncryptionClient.decrypt_message_content: decrypt message content key_uri=%s content_length=%s",
            encryption_key_url,
            len(encrypted_content),
        )
        return await self.decrypt_text(encryption_key_url, encrypted_content)

    async def _retrieve_and_cache_key(self, key_uri: str) -> Key:
        """Retrieve a key and store it in the cache when configured.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        log.debug("EncryptionClient._retrieve_and_cache_key: retrieve key key_uri=%s", key_uri)
        key = await self._retrieve_key_from_kms(key_uri)
        if not self._config.disable_key_cache:
            async with self._key_cache_lock:
                log.debug(
                    "EncryptionClient._retrieve_and_cache_key: store retrieved key key_uri=%s",
                    key_uri,
                )
                self._key_cache[key_uri] = key
        return key

    async def _retrieve_key_from_kms(self, key_uri: str) -> Key:
        """Retrieve a key through the supported KMS transport.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        log.debug(
            "EncryptionClient._retrieve_key_from_kms: select KMS retrieval transport key_uri=%s",
            key_uri,
        )
        return await self._retrieve_key_via_ecdh(key_uri)

    async def _retrieve_key_via_ecdh(self, key_uri: str) -> Key:
        """Retrieve a KMS key using an ECDH session.

        :param key_uri: KMS key URI to retrieve.
        :returns: Retrieved ``Key`` model.
        """
        log.debug(
            "EncryptionClient._retrieve_key_via_ecdh: retrieve key via ECDH key_uri=%s",
            key_uri,
        )
        ecdh_context = await self._get_or_create_ecdh()
        try:
            return await self._do_kms_retrieve(key_uri, ecdh_context)
        except Exception as err:
            # Session-level failures get one fresh ECDH exchange before surfacing.
            if _is_ecdh_session_error(err):
                log.debug(
                    "EncryptionClient._retrieve_key_via_ecdh: refresh ECDH after session error",
                    exc_info=True,
                )
                await self._invalidate_ecdh()
                retry_context = await self._get_or_create_ecdh()
                try:
                    return await self._do_kms_retrieve(key_uri, retry_context)
                except Exception as retry_err:
                    raise KMSProtocolError(f"retry KMS retrieve failed: {retry_err} (original: {err})") from retry_err

            try:
                # Non-session failures get one retry against the same context for transient errors.
                log.debug(
                    "EncryptionClient._retrieve_key_via_ecdh: retry KMS retrieve with same ECDH context",
                    exc_info=True,
                )
                return await self._do_kms_retrieve(key_uri, ecdh_context)
            except Exception as retry_err:
                raise KMSProtocolError(f"retry KMS retrieve failed: {retry_err} (original: {err})") from retry_err

    async def _do_kms_retrieve(self, key_uri: str, ecdh_context: ECDHContext) -> Key:
        """Send one retrieve request through an established ECDH context.

        :param key_uri: KMS key URI to retrieve.
        :param ecdh_context: Active ECDH context used to wrap the request.
        :returns: Retrieved ``Key`` model.
        """
        # Resolve caller identity and register a future for possible Mercury delivery.
        log.debug("EncryptionClient._do_kms_retrieve: prepare KMS retrieve key_uri=%s", key_uri)
        user_id = await self._get_user_id()
        request_id = generate_request_id()
        future = await self._register_pending_request(request_id)

        # Select the destination cluster from the key URI domain.
        domain, _ = parse_kms_uri(key_uri)
        destination = kms_cluster_from_domain(domain, ecdh_context.kms_cluster)
        log.debug(
            "EncryptionClient._do_kms_retrieve: build KMS retrieve request request_id=%s destination=%s domain=%s",
            request_id,
            destination,
            domain,
        )
        # Build the KMS retrieve payload expected by the encrypted endpoint.
        kms_request = {
            "client": {
                "clientId": self._get_client_id(),
                "credential": {
                    "userId": decode_webex_id(user_id),
                    "bearer": self._core.access_token,
                },
            },
            "requestId": request_id,
            "method": "retrieve",
            "uri": key_uri,
        }

        try:
            # Wrap the retrieve payload with the shared ECDH secret.
            log.debug(
                "EncryptionClient._do_kms_retrieve: wrap KMS retrieve request request_id=%s",
                request_id,
            )
            wrapped_request = wrap_with_shared_secret(
                json.dumps(kms_request, separators=(",", ":")).encode("utf-8"),
                ecdh_context.shared_secret,
                ecdh_context.ecdh_key_uri,
            )
            response_jwes = await self._send_kms_message(wrapped_request, destination)
            # A 200 response carries KMS replies synchronously in the HTTP response.
            if response_jwes:
                log.debug(
                    "EncryptionClient._do_kms_retrieve: process synchronous KMS response request_id=%s count=%s",
                    request_id,
                    len(response_jwes),
                )
                return self._process_key_response_jwes(response_jwes, ecdh_context)

            # A 202 response means the reply will arrive later over Mercury.
            log.debug(
                "EncryptionClient._do_kms_retrieve: await Mercury KMS response request_id=%s timeout=%s",
                request_id,
                self._config.kms_response_timeout,
            )
            payload = await asyncio.wait_for(future, timeout=self._config.kms_response_timeout)
            return self._parse_key_from_payload(payload)
        finally:
            log.debug(
                "EncryptionClient._do_kms_retrieve: unregister pending KMS request request_id=%s",
                request_id,
            )
            self._unregister_pending_request(request_id)

    async def _get_or_create_ecdh(self) -> ECDHContext:
        """Return a valid cached ECDH context or create a new one.

        :returns: Active ``ECDHContext``.
        """
        async with self._ecdh_lock:
            log.debug("EncryptionClient._get_or_create_ecdh: inspect cached ECDH context")
            if self._ecdh_context is not None:
                # Reuse the cached context until its TTL expires.
                if time.time() - self._ecdh_context.created_at < ECDH_TTL_SECONDS:
                    log.debug(
                        "EncryptionClient._get_or_create_ecdh: reuse cached ECDH context key_uri=%s",
                        self._ecdh_context.ecdh_key_uri,
                    )
                    return self._ecdh_context
                log.debug("EncryptionClient._get_or_create_ecdh: expire cached ECDH context")
                self._ecdh_context = None

            # Create and cache a fresh context while holding the lock to avoid duplicate exchanges.
            log.debug("EncryptionClient._get_or_create_ecdh: perform new ECDH exchange")
            self._ecdh_context = await self._perform_ecdh_exchange()
            return self._ecdh_context

    async def _invalidate_ecdh(self) -> None:
        """Clear the cached ECDH context.

        :returns: None.
        """
        log.debug("EncryptionClient._invalidate_ecdh: clear cached ECDH context")
        async with self._ecdh_lock:
            self._ecdh_context = None

    async def _perform_ecdh_exchange(self) -> ECDHContext:
        """Perform an ECDH create request with KMS.

        :returns: Newly established ``ECDHContext``.
        """
        # Fetch user and KMS cluster metadata before generating client key material.
        log.debug("EncryptionClient._perform_ecdh_exchange: fetch user and KMS metadata")
        user_id = await self._get_user_id()
        kms_info = await self._get_kms_info(user_id)
        rsa_public_key, rsa_kid = parse_rsa_public_key_from_json(kms_info.rsa_public_key)
        local_private_key = ec.generate_private_key(ec.SECP256R1())
        # Ask KMS to create the remote ECDH key and derive the shared secret.
        log.debug(
            "EncryptionClient._perform_ecdh_exchange: send ECDH create request cluster=%s rsa_kid=%s",
            kms_info.kms_cluster,
            rsa_kid,
        )
        ecdh_response = await self._send_ecdh_request(
            local_private_key,
            rsa_public_key,
            rsa_kid,
            kms_info.kms_cluster,
            user_id,
        )
        shared_secret = derive_shared_secret(ecdh_response, local_private_key)
        ecdh_key_uri = ecdh_response.key.uri if ecdh_response.key is not None else ""
        # Keep the local private key and metadata for future wrapped retrieve calls.
        log.debug(
            "EncryptionClient._perform_ecdh_exchange: create ECDH context key_uri=%s cluster=%s",
            ecdh_key_uri,
            kms_info.kms_cluster,
        )
        return ECDHContext(
            local_private_key=local_private_key,
            shared_secret=shared_secret,
            ecdh_key_uri=ecdh_key_uri,
            kms_cluster=kms_info.kms_cluster,
            created_at=time.time(),
        )

    async def _send_ecdh_request(
        self,
        local_private_key: ec.EllipticCurvePrivateKey,
        rsa_public_key: rsa.RSAPublicKey,
        rsa_kid: str,
        cluster: str,
        user_id: str,
    ) -> KMSMessage:
        """Send the ECDH create request that establishes a shared KMS secret.

        :param local_private_key: Client EC private key for the exchange.
        :param rsa_public_key: KMS RSA key used to wrap the create request.
        :param rsa_kid: KMS RSA key identifier.
        :param cluster: KMS cluster destination.
        :param user_id: Webex user ID used in the KMS credential block.
        :returns: KMS response message containing KMS-side ECDH public material.
        """
        # Register the request with the EC private key for possible async response decryption.
        log.debug(
            "EncryptionClient._send_ecdh_request: prepare ECDH create request cluster=%s rsa_kid=%s",
            cluster,
            rsa_kid,
        )
        request_id = generate_request_id()
        future = await self._register_pending_request(request_id, local_private_key)
        client_pub_jwk = ec_public_key_to_jwk(local_private_key.public_key())
        # Build a KMS create request for an ephemeral ECDH key.
        log.debug(
            "EncryptionClient._send_ecdh_request: build KMS create request request_id=%s",
            request_id,
        )
        ecdh_request = {
            "client": {
                "clientId": self._get_client_id(),
                "credential": {
                    "userId": decode_webex_id(user_id),
                    "bearer": self._core.access_token,
                },
            },
            "requestId": request_id,
            "method": "create",
            "uri": "/ecdhe",
            "jwk": client_pub_jwk.to_dict(include_private=False),
        }
        try:
            # Wrap the create request with the cluster RSA public key.
            log.debug(
                "EncryptionClient._send_ecdh_request: wrap KMS create request request_id=%s",
                request_id,
            )
            wrapped = wrap_with_rsa(
                json.dumps(ecdh_request, separators=(",", ":")).encode("utf-8"),
                rsa_public_key,
                rsa_kid,
            )
            response_jwes = await self._send_kms_message(wrapped, cluster.removeprefix("kms://"))
            # Process synchronous HTTP replies immediately.
            if response_jwes:
                log.debug(
                    "EncryptionClient._send_ecdh_request: process synchronous ECDH response request_id=%s count=%s",
                    request_id,
                    len(response_jwes),
                )
                return decrypt_ecdh_response(response_jwes, local_private_key)

            # Await asynchronous Mercury delivery for accepted requests.
            log.debug(
                "EncryptionClient._send_ecdh_request: await Mercury ECDH response request_id=%s timeout=%s",
                request_id,
                self._config.kms_response_timeout,
            )
            payload = await asyncio.wait_for(future, timeout=self._config.kms_response_timeout)
            parsed = json.loads(payload)
            if not isinstance(parsed, dict):
                raise KMSProtocolError("ECDH response payload is not an object")
            return KMSMessage.from_dict(parsed)
        finally:
            log.debug(
                "EncryptionClient._send_ecdh_request: unregister pending ECDH request request_id=%s",
                request_id,
            )
            self._unregister_pending_request(request_id)

    async def _get_user_id(self) -> str:
        """Return the cached or API-derived Webex user ID.

        :returns: Webex user ID.
        """
        if self._user_id:
            log.debug("EncryptionClient._get_user_id: use cached user ID")
            return self._user_id
        # Fall back to people/me when device registration has not supplied the user ID.
        log.debug("EncryptionClient._get_user_id: send people/me API request")
        response = await self._core.request_url(
            "GET",
            "https://webexapis.com/v1/people/me",
            headers={"Accept": "application/json"},
        )
        if response.status_code != 200:
            log.debug(
                "EncryptionClient._get_user_id: people/me API error status=%s response=%s",
                response.status_code,
                response.text,
            )
            raise api_error_from_response(response)
        user_id = str(response.json().get("id") or "")
        if not user_id:
            raise KMSProtocolError("user ID is empty in people/me response")
        self._user_id = user_id
        log.debug("EncryptionClient._get_user_id: cache user ID present=%s", bool(user_id))
        return user_id

    async def _get_kms_info(self, user_id: str) -> KMSInfo:
        """Fetch KMS cluster metadata for a user.

        :param user_id: Webex user ID in encoded or UUID form.
        :returns: ``KMSInfo`` containing the target cluster and RSA public key payload.
        """
        # KMS info endpoints expect the decoded UUID form of the Webex user ID.
        kms_user_id = decode_webex_id(user_id)
        cluster = self._config.kms_default_cluster
        url = f"https://encryption-{cluster}.wbx2.com/encryption/api/v1/kms/{kms_user_id}"
        log.debug(
            "EncryptionClient._get_kms_info: send KMS info API request cluster=%s user_id=%s",
            cluster,
            kms_user_id,
        )
        response = await self._core.request_url("GET", url, headers={"Accept": "application/json"})
        if response.status_code != 200:
            log.debug(
                "EncryptionClient._get_kms_info: KMS info API error status=%s response=%s",
                response.status_code,
                response.text,
            )
            raise api_error_from_response(response)
        data = response.json()
        # Preserve the raw RSA field because KMS may return either JWK or JWKS shape.
        log.debug(
            "EncryptionClient._get_kms_info: receive KMS info API response cluster=%s rsa_present=%s",
            data.get("kmsCluster") if isinstance(data, dict) else "",
            bool(data.get("rsaPublicKey")) if isinstance(data, dict) else False,
        )
        return KMSInfo(
            kms_cluster=str(data.get("kmsCluster") or ""),
            rsa_public_key=data.get("rsaPublicKey"),
        )

    async def _send_kms_message(self, wrapped_message: str, destination: str) -> list[str] | None:
        """Send one wrapped KMS message to the messages endpoint.

        :param wrapped_message: Compact JWE request payload.
        :param destination: KMS destination cluster or host.
        :returns: List of synchronous KMS response JWEs, or ``None`` for async delivery.
        """
        # Wrap the message in the HTTP envelope accepted by KMS.
        envelope: dict[str, Any] = {"kmsMessages": [wrapped_message]}
        if destination:
            envelope["destination"] = destination
        url = f"https://encryption-{self._config.kms_default_cluster}.wbx2.com/encryption/api/v1/kms/messages"
        log.debug(
            "EncryptionClient._send_kms_message: send KMS API message url=%s destination=%s message_length=%s",
            url,
            destination,
            len(wrapped_message),
        )
        response = await self._core.request_url("POST", url, json=envelope)
        if response.status_code == 202:
            log.debug("EncryptionClient._send_kms_message: KMS API accepted async response status=202")
            return None
        if response.status_code != 200:
            log.debug(
                "EncryptionClient._send_kms_message: KMS API error status=%s response=%s",
                response.status_code,
                response.text,
            )
            raise KMSProtocolError(f"KMS request failed with status {response.status_code}: {response.text}")
        data = response.json()
        # Normalize response message values to strings for downstream decrypt helpers.
        response_messages = [str(value) for value in data.get("kmsMessages") or []]
        log.debug(
            "EncryptionClient._send_kms_message: KMS API synchronous response status=%s count=%s",
            response.status_code,
            len(response_messages),
        )
        return response_messages

    async def _register_pending_request(
        self,
        request_id: str,
        ecdh_private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> asyncio.Future[bytes]:
        """Register a pending KMS request for asynchronous Mercury completion.

        :param request_id: KMS request ID to match against future responses.
        :param ecdh_private_key: Optional private key needed to decrypt ECDH create replies.
        :returns: Future that will receive the raw response payload.
        """
        log.debug(
            "EncryptionClient._register_pending_request: register pending KMS request "
            "request_id=%s ecdh_private_key=%s",
            request_id,
            ecdh_private_key is not None,
        )
        future: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        async with self._pending_lock:
            self._pending_requests[request_id] = PendingKMSRequest(future, ecdh_private_key)
        return future

    def _unregister_pending_request(self, request_id: str) -> None:
        """Remove a pending KMS request registration.

        :param request_id: KMS request ID to remove.
        :returns: None.
        """
        log.debug(
            "EncryptionClient._unregister_pending_request: unregister pending KMS request request_id=%s",
            request_id,
        )
        self._pending_requests.pop(request_id, None)

    def _process_key_response_jwes(self, response_jwes: list[str], ecdh_context: ECDHContext) -> Key:
        """Decrypt synchronous key response JWEs and parse the first valid key.

        :param response_jwes: Compact JWE responses returned by KMS.
        :param ecdh_context: ECDH context whose shared secret decrypts the responses.
        :returns: Retrieved ``Key`` model.
        """
        # Try each response until one decrypts and contains a usable key payload.
        log.debug(
            "EncryptionClient._process_key_response_jwes: process KMS response JWEs count=%s",
            len(response_jwes),
        )
        for response_jwe in response_jwes:
            try:
                payload = unwrap_with_shared_secret(response_jwe, ecdh_context.shared_secret)
            except Exception:
                log.debug(
                    "EncryptionClient._process_key_response_jwes: skip undecryptable KMS response JWE",
                    exc_info=True,
                )
                continue
            return self._parse_key_from_payload(payload)
        raise KMSProtocolError("no key found in KMS response JWEs")

    def _parse_key_from_payload(self, payload: bytes) -> Key:
        """Parse a KMS payload and extract its key material.

        :param payload: Raw JSON KMS response bytes.
        :returns: Retrieved ``Key`` model.
        """
        log.debug(
            "EncryptionClient._parse_key_from_payload: parse KMS key payload bytes=%s",
            len(payload),
        )
        parsed = json.loads(payload)
        if not isinstance(parsed, dict):
            raise KMSProtocolError("KMS response payload is not an object")
        response = KMSMessage.from_dict(parsed)
        if not response.is_success():
            raise KMSProtocolError(f"KMS request failed with status: {response.status}")
        # KMS can return either a single key or a list of keys for retrieve responses.
        if response.key is not None:
            log.debug(
                "EncryptionClient._parse_key_from_payload: return single KMS key uri=%s",
                response.key.uri,
            )
            return response.key
        if response.keys:
            log.debug(
                "EncryptionClient._parse_key_from_payload: return first KMS key count=%s uri=%s",
                len(response.keys),
                response.keys[0].uri,
            )
            return response.keys[0]
        raise KMSProtocolError("no key found in KMS response")

    def _get_client_id(self) -> str:
        """Return the client identifier used in KMS requests.

        :returns: Device URL when available, otherwise a stable SDK fallback identifier.
        """
        log.debug(
            "EncryptionClient._get_client_id: resolve KMS client ID device_url_present=%s",
            bool(self._device_url),
        )
        return self._device_url or "webex-kms-sdk-client"


def parse_kms_uri(key_uri: str) -> tuple[str, str]:
    """Split a KMS URI into domain and resource path.

    :param key_uri: URI beginning with ``kms://``.
    :returns: Tuple of ``(domain, resource_path)``.
    """
    # Validate the URI prefix and required domain/path structure.
    log.debug("parse_kms_uri: parse KMS URI key_uri=%s", key_uri)
    if not key_uri.startswith(KMS_URI_PREFIX):
        raise ValueError(f"invalid KMS URI format (missing prefix): {key_uri}")
    without_prefix = key_uri[len(KMS_URI_PREFIX) :]
    parts = without_prefix.split("/", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"invalid KMS URI format (invalid structure): {key_uri}")
    log.debug("parse_kms_uri: parsed KMS URI domain=%s path=%s", parts[0], parts[1])
    return parts[0], parts[1]


def kms_cluster_from_domain(domain: str, default_kms_cluster: str) -> str:
    """Choose a KMS destination cluster from a KMS URI domain.

    :param domain: Domain portion of a KMS URI.
    :param default_kms_cluster: Fallback cluster when the domain is not cluster-like.
    :returns: Cluster or cluster host suitable for KMS message destination.
    """

    def clean(value: str) -> str:
        """Remove an optional KMS URI prefix from a cluster value.

        :param value: Cluster or domain value to normalize.
        :returns: Value without a leading ``kms://`` prefix.
        """
        return value.removeprefix("kms://")

    # Empty or non-cluster domains fall back to the configured default cluster.
    log.debug(
        "kms_cluster_from_domain: resolve KMS cluster domain=%s default=%s",
        domain,
        default_kms_cluster,
    )
    if not domain:
        return clean(default_kms_cluster)
    domain = clean(domain)
    if domain.startswith("kms-") and ".wbx2.com" in domain:
        return domain
    if len(domain) <= 5 and "." not in domain:
        return domain
    return clean(default_kms_cluster)


def get_cluster_from_domain(domain: str, default_cluster: str) -> str:
    """Infer the short KMS cluster name from a domain.

    :param domain: KMS domain, short cluster, or organization domain.
    :param default_cluster: Fallback cluster name.
    :returns: Short cluster name such as ``a``.
    """
    log.debug(
        "get_cluster_from_domain: infer KMS cluster domain=%s default=%s",
        domain,
        default_cluster,
    )
    if not domain:
        return default_cluster
    # Full KMS hosts encode the cluster between the kms- prefix and first dot.
    if domain.startswith("kms-") and ".wbx2.com" in domain:
        rest = domain.removeprefix("kms-")
        cluster = rest.split(".", 1)[0]
        if cluster:
            return cluster
    if len(domain) <= 5 and "." not in domain:
        return domain
    # Cisco-owned domains default to the primary cluster.
    if domain in {"cisco.com", "ciscospark.com"}:
        return "a"
    return default_cluster


def generate_request_id() -> str:
    """Generate a KMS request ID using the SDK-compatible prefix.

    :returns: Random request ID string.
    """
    data = os.urandom(16)
    request_id = (
        f"python-sdk-{data[0:4].hex()}-{data[4:6].hex()}-{data[6:8].hex()}-{data[8:10].hex()}-{data[10:16].hex()}"
    )
    log.debug("generate_request_id: generate KMS request ID request_id=%s", request_id)
    return request_id


def decode_webex_id(value: str) -> str:
    """Decode a Webex ID into a UUID when it is base64url encoded.

    :param value: UUID or base64url-encoded Webex resource ID.
    :returns: UUID if decoding succeeds and yields one, otherwise the original value.
    """
    log.debug("decode_webex_id: decode Webex ID value_present=%s", bool(value))
    if UUID_RE.match(value):
        return value
    try:
        decoded = _b64url_decode(value).decode("utf-8")
    except Exception:
        return value
    # Webex resource IDs usually end with the UUID after the final slash.
    candidate = decoded.rsplit("/", 1)[-1]
    result = candidate if UUID_RE.match(candidate) else value
    log.debug("decode_webex_id: decoded Webex ID changed=%s", result != value)
    return result


def wrap_with_shared_secret(payload: bytes, shared_secret: bytes, kid: str = "") -> str:
    """Encrypt a payload as compact JWE using a direct shared secret.

    :param payload: Plaintext bytes to encrypt.
    :param shared_secret: Raw symmetric key bytes.
    :param kid: Optional key ID to include in the protected header.
    :returns: Compact serialized JWE string.
    """
    log.debug(
        "wrap_with_shared_secret: wrap payload bytes=%s kid_present=%s",
        len(payload),
        bool(kid),
    )
    key = jose_jwk.JWK(kty="oct", k=_b64url_encode(shared_secret))
    protected = {"alg": "dir", "enc": "A256GCM"}
    if kid:
        protected["kid"] = kid
    token = jwe.JWE(payload, protected=protected)  # type: ignore[arg-type]
    token.add_recipient(key)
    wrapped = token.serialize(compact=True)
    log.debug("wrap_with_shared_secret: wrapped payload length=%s", len(wrapped))
    return wrapped


def unwrap_with_shared_secret(jwe_string: str, shared_secret: bytes) -> bytes:
    """Decrypt compact JWE payload encrypted with a direct shared secret.

    :param jwe_string: Compact JWE string to decrypt.
    :param shared_secret: Raw symmetric key bytes.
    :returns: Decrypted payload bytes.
    """
    log.debug("unwrap_with_shared_secret: unwrap JWE length=%s", len(jwe_string))
    key = jose_jwk.JWK(kty="oct", k=_b64url_encode(shared_secret))
    token = jwe.JWE()
    token.deserialize(jwe_string, key=key)
    payload = token.payload
    plaintext = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    log.debug("unwrap_with_shared_secret: unwrapped payload bytes=%s", len(plaintext))
    return plaintext


def wrap_with_rsa(payload: bytes, rsa_public_key: rsa.RSAPublicKey, kid: str = "") -> str:
    """Encrypt a payload as compact JWE using an RSA public key.

    :param payload: Plaintext bytes to encrypt.
    :param rsa_public_key: RSA public key used for key wrapping.
    :param kid: Optional key ID to include in the protected header.
    :returns: Compact serialized JWE string.
    """
    # Convert cryptography RSA numbers into the JWK shape expected by jwcrypto.
    log.debug("wrap_with_rsa: wrap payload with RSA bytes=%s kid_present=%s", len(payload), bool(kid))
    public_numbers = rsa_public_key.public_numbers()
    key = jose_jwk.JWK(
        kty="RSA",
        n=_int_to_b64url(public_numbers.n),
        e=_int_to_b64url(public_numbers.e),
    )
    protected = {"alg": "RSA-OAEP", "enc": "A256GCM"}
    if kid:
        protected["kid"] = kid
    token = jwe.JWE(payload, protected=protected)  # type: ignore[arg-type]
    token.add_recipient(key)
    wrapped = token.serialize(compact=True)
    log.debug("wrap_with_rsa: wrapped payload length=%s", len(wrapped))
    return wrapped


def decrypt_ecdh_response(
    response_jwes: list[str],
    local_private_key: ec.EllipticCurvePrivateKey,
) -> KMSMessage:
    """Decrypt ECDH response JWEs and parse the first valid KMS message.

    :param response_jwes: Compact JWE responses from KMS.
    :param local_private_key: EC private key generated for the ECDH request.
    :returns: Parsed ``KMSMessage`` containing ECDH response material.
    """
    # Try each response because KMS can return multiple messages in one envelope.
    log.debug("decrypt_ecdh_response: decrypt ECDH response JWEs count=%s", len(response_jwes))
    for response_jwe in response_jwes:
        try:
            plaintext = _decrypt_ecdh_jwe(response_jwe, local_private_key)
        except Exception:
            log.debug("decrypt_ecdh_response: skip undecryptable ECDH response", exc_info=True)
            continue
        try:
            parsed = json.loads(plaintext)
        except json.JSONDecodeError:
            log.debug("decrypt_ecdh_response: skip invalid ECDH response JSON")
            continue
        if isinstance(parsed, dict):
            log.debug("decrypt_ecdh_response: parse ECDH KMS response message")
            return KMSMessage.from_dict(parsed)
    raise KMSProtocolError("failed to decrypt ECDH response from KMS")


def derive_shared_secret(
    ecdh_response: KMSMessage,
    local_private_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    """Derive the KMS ECDH shared secret from a response message.

    :param ecdh_response: KMS response containing server EC public key material.
    :param local_private_key: Client EC private key for the exchange.
    :returns: 32-byte shared secret derived with HKDF-SHA256.
    """
    log.debug("derive_shared_secret: derive ECDH shared secret")
    server_jwk = extract_server_ec_key(ecdh_response)
    if server_jwk is None:
        raise KMSProtocolError("KMS ECDH response missing EC public key")
    # Perform ECDH and normalize the raw secret through HKDF for symmetric JWE use.
    server_public_key = jwk_to_ec_public_key(server_jwk)
    raw_secret = local_private_key.exchange(ec.ECDH(), server_public_key)
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(raw_secret)
    log.debug("derive_shared_secret: derived ECDH shared secret bytes=%s", len(shared_secret))
    return shared_secret


def extract_server_ec_key(response: KMSMessage) -> JWK | None:
    """Extract server EC public key material from a KMS ECDH response.

    :param response: Parsed KMS response message.
    :returns: Server EC ``JWK`` when present, otherwise ``None``.
    """
    log.debug("extract_server_ec_key: extract server EC key")
    if response.key is not None and response.key.jwk.kty == "EC":
        return response.key.jwk
    if response.jwk is not None and response.jwk.kty == "EC":
        return response.jwk
    return None


def ec_public_key_to_jwk(public_key: ec.EllipticCurvePublicKey) -> JWK:
    """Convert an EC public key to a P-256 JWK.

    :param public_key: EC public key to serialize.
    :returns: Public ``JWK`` containing curve coordinates.
    """
    log.debug("ec_public_key_to_jwk: convert EC public key to JWK")
    numbers = public_key.public_numbers()
    return JWK(
        kty="EC",
        crv="P-256",
        x=_b64url_encode(_pad_to_32(numbers.x.to_bytes(32, "big"))),
        y=_b64url_encode(_pad_to_32(numbers.y.to_bytes(32, "big"))),
    )


def jwk_to_ec_public_key(value: JWK) -> ec.EllipticCurvePublicKey:
    """Convert a P-256 EC JWK into a cryptography public key.

    :param value: JWK containing P-256 public coordinates.
    :returns: EC public key object.
    """
    log.debug("jwk_to_ec_public_key: convert JWK to EC public key kid=%s", value.kid)
    if value.kty != "EC" or value.crv != "P-256":
        raise ValueError(f"unsupported key type/curve: {value.kty}/{value.crv}")
    x = int.from_bytes(_b64url_decode(value.x), "big")
    y = int.from_bytes(_b64url_decode(value.y), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def parse_rsa_public_key_from_json(raw: Any) -> tuple[rsa.RSAPublicKey, str]:
    """Parse an RSA public key from KMS JWK or JWKS data.

    :param raw: KMS RSA public key field as a dictionary, JSON string, or JWKS dictionary.
    :returns: Tuple of RSA public key object and key ID.
    """
    log.debug("parse_rsa_public_key_from_json: parse KMS RSA public key type=%s", type(raw).__name__)
    candidate = raw
    # KMS may return the RSA key field as a serialized JSON string.
    if isinstance(candidate, str):
        try:
            candidate = json.loads(candidate)
        except json.JSONDecodeError:
            raise ValueError("unable to parse RSA public key from KMS info response") from None

    if isinstance(candidate, dict) and candidate.get("kty") == "RSA":
        key = JWK.from_dict(candidate)
        log.debug("parse_rsa_public_key_from_json: parsed direct RSA JWK kid=%s", key.kid)
        return jwk_to_rsa_public_key(key), key.kid

    # JWKS payloads are scanned for the first RSA key entry.
    if isinstance(candidate, dict) and isinstance(candidate.get("keys"), list):
        for entry in candidate["keys"]:
            if isinstance(entry, dict) and entry.get("kty") == "RSA":
                key = JWK.from_dict(entry)
                log.debug("parse_rsa_public_key_from_json: parsed JWKS RSA key kid=%s", key.kid)
                return jwk_to_rsa_public_key(key), key.kid

    raise ValueError("unable to parse RSA public key from KMS info response")


def jwk_to_rsa_public_key(value: JWK) -> rsa.RSAPublicKey:
    """Convert an RSA JWK into a cryptography public key.

    :param value: RSA JWK containing modulus and exponent.
    :returns: RSA public key object.
    """
    log.debug("jwk_to_rsa_public_key: convert RSA JWK kid=%s", value.kid)
    if value.kty != "RSA":
        raise ValueError(f"key type is {value.kty!r}, expected RSA")
    if not value.n or not value.e:
        raise ValueError("RSA key missing modulus (n) or exponent (e)")
    n = int.from_bytes(_b64url_decode(value.n), "big")
    e = int.from_bytes(_b64url_decode(value.e), "big")
    if n.bit_length() < 2048:
        raise ValueError(f"RSA key size {n.bit_length()} bits is too small")
    log.debug("jwk_to_rsa_public_key: converted RSA public key bits=%s", n.bit_length())
    return rsa.RSAPublicNumbers(e, n).public_key()


def _decrypt_ecdh_jwe(jwe_string: str, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Decrypt a compact ECDH response JWE with the local EC private key.

    :param jwe_string: Compact JWE string to decrypt.
    :param private_key: EC private key generated for the request.
    :returns: Decrypted payload bytes.
    """
    log.debug("_decrypt_ecdh_jwe: decrypt ECDH JWE length=%s", len(jwe_string))
    key = _ec_private_key_to_jwk(private_key)
    token = jwe.JWE()
    token.deserialize(jwe_string, key=key)
    payload = token.payload
    plaintext = payload if isinstance(payload, bytes) else payload.encode("utf-8")
    log.debug("_decrypt_ecdh_jwe: decrypted ECDH payload bytes=%s", len(plaintext))
    return plaintext


def _ec_private_key_to_jwk(private_key: ec.EllipticCurvePrivateKey) -> jose_jwk.JWK:
    """Convert an EC private key to a jwcrypto JWK.

    :param private_key: EC private key to serialize.
    :returns: jwcrypto JWK with public coordinates and private scalar.
    """
    log.debug("_ec_private_key_to_jwk: convert EC private key to JWK")
    numbers = private_key.private_numbers()
    public = numbers.public_numbers
    return jose_jwk.JWK(
        kty="EC",
        crv="P-256",
        x=_b64url_encode(public.x.to_bytes(32, "big")),
        y=_b64url_encode(public.y.to_bytes(32, "big")),
        d=_b64url_encode(numbers.private_value.to_bytes(32, "big")),
    )


def _is_ecdh_session_error(err: BaseException) -> bool:
    """Return whether an exception suggests the ECDH session should be refreshed.

    :param err: Exception raised during a KMS request.
    :returns: ``True`` when the error message matches known session-failure markers.
    """
    message = str(err)
    result = any(marker in message for marker in ("status 400", "status 403", "error decrypting", "failed with status"))
    log.debug("_is_ecdh_session_error: classify ECDH error result=%s message=%s", result, message)
    return result


def _b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url text.

    :param data: Bytes to encode.
    :returns: ASCII base64url string without padding.
    """
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    log.debug("_b64url_encode: encode bytes input=%s output_length=%s", len(data), len(encoded))
    return encoded


def _b64url_decode(value: str) -> bytes:
    """Decode base64url text with optional omitted padding.

    :param value: Base64url string to decode.
    :returns: Decoded bytes.
    """
    log.debug("_b64url_decode: decode base64url length=%s", len(value))
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _int_to_b64url(value: int) -> str:
    """Encode an integer as unpadded base64url bytes.

    :param value: Integer to encode.
    :returns: Base64url representation of the minimal big-endian byte string.
    """
    length = max(1, (value.bit_length() + 7) // 8)
    log.debug("_int_to_b64url: encode integer bits=%s bytes=%s", value.bit_length(), length)
    return _b64url_encode(value.to_bytes(length, "big"))


def _pad_to_32(data: bytes) -> bytes:
    """Left-pad or trim a byte string to exactly 32 bytes.

    :param data: Byte string to normalize.
    :returns: Exactly 32 bytes.
    """
    log.debug("_pad_to_32: normalize byte string length=%s", len(data))
    if len(data) >= 32:
        return data[-32:]
    return b"\x00" * (32 - len(data)) + data
