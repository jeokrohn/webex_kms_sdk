from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time

import httpx
import pytest
import respx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from webex_kms_sdk import JWK, Config, Key, KMSMessage, WebexClient
from webex_kms_sdk.encryption import (
    ECDHContext,
    derive_shared_secret,
    ec_public_key_to_jwk,
    generate_request_id,
    get_cluster_from_domain,
    kms_cluster_from_domain,
    parse_kms_uri,
    parse_rsa_public_key_from_json,
    wrap_with_shared_secret,
)


def b64url(data: bytes) -> str:
    """Encode bytes as unpadded base64url text for test JWK values.

    :param data: Bytes to encode.
    :returns: Base64url string without padding.
    """
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def test_jwk_symmetric_key() -> None:
    """Verify octet JWK values decode to symmetric key bytes.

    :returns: None.
    """
    # Arrange a random symmetric key encoded into an octet JWK.
    raw_key = os.urandom(32)
    jwk = JWK(kty="oct", k=b64url(raw_key), kid="kid-1")

    # Assert the JWK helper returns the original raw key.
    assert jwk.symmetric_key() == raw_key


def test_parse_kms_uri_and_cluster_helpers() -> None:
    """Verify KMS URI parsing and cluster inference helpers.

    :returns: None.
    """
    # Assert valid KMS URIs split into domain and path.
    assert parse_kms_uri("kms://ciscospark.com/keys/abc") == ("ciscospark.com", "keys/abc")

    # Assert malformed URI schemes are rejected.
    with pytest.raises(ValueError):
        parse_kms_uri("https://example.test/key")

    # Assert domain and default cluster inputs map to expected destinations.
    assert kms_cluster_from_domain("kms-a.wbx2.com", "kms-b.wbx2.com") == "kms-a.wbx2.com"
    assert kms_cluster_from_domain("ciscospark.com", "kms-b.wbx2.com") == "kms-b.wbx2.com"
    assert get_cluster_from_domain("kms-c.wbx2.com", "a") == "c"
    assert get_cluster_from_domain("cisco.com", "b") == "a"


def test_wrap_unwrap_with_shared_secret() -> None:
    """Verify direct shared-secret JWE wrapping round-trips payload bytes.

    :returns: None.
    """
    from webex_kms_sdk.encryption import unwrap_with_shared_secret

    # Arrange a payload and shared secret.
    secret = os.urandom(32)
    payload = b'{"method":"retrieve","uri":"kms://test/keys/1"}'

    # Act by wrapping, then assert the compact JWE decrypts to the original payload.
    wrapped = wrap_with_shared_secret(payload, secret, "kms://test/ecdhe/1")
    assert wrapped.count(".") == 4
    assert unwrap_with_shared_secret(wrapped, secret) == payload


def test_ecdh_shared_secret_derivation() -> None:
    """Verify client and server ECDH material derive the same shared secret.

    :returns: None.
    """
    # Arrange matching client/server EC keypairs and a KMS-like response.
    client_private = ec.generate_private_key(ec.SECP256R1())
    server_private = ec.generate_private_key(ec.SECP256R1())
    server_jwk = ec_public_key_to_jwk(server_private.public_key())
    response = KMSMessage(key=Key(uri="kms://test/ecdhe/1", jwk=server_jwk))

    # Act by deriving the client-side secret and the expected server-side secret.
    client_secret = derive_shared_secret(response, client_private)
    raw_server_secret = server_private.exchange(ec.ECDH(), client_private.public_key())
    server_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=None,
    ).derive(raw_server_secret)

    # Assert both sides agree on the HKDF-normalized secret.
    assert client_secret == server_secret
    assert len(client_secret) == 32


def test_parse_rsa_public_key_from_jwk_and_jwks() -> None:
    """Verify RSA public keys parse from JWK and JWKS shapes.

    :returns: None.
    """
    # Arrange an RSA JWK from generated public key numbers.
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    rsa_jwk = {
        "kty": "RSA",
        "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        "kid": "rsa-kid",
    }

    # Act and assert direct JWK parsing preserves key material and key ID.
    parsed_key, kid = parse_rsa_public_key_from_json(rsa_jwk)
    assert parsed_key.public_numbers().n == numbers.n
    assert kid == "rsa-kid"

    # Act and assert JWKS parsing finds the RSA entry.
    parsed_key, kid = parse_rsa_public_key_from_json({"keys": [rsa_jwk]})
    assert parsed_key.public_numbers().e == 65537
    assert kid == "rsa-kid"


def test_process_kms_messages_caches_key() -> None:
    """Verify processed KMS messages cache returned key material.

    :returns: None.
    """
    # Arrange an encryption client with an active ECDH context.
    client = WebexClient("test-token")
    encryption = client.encryption
    shared_secret = os.urandom(32)
    encryption._ecdh_context = ECDHContext(
        local_private_key=ec.generate_private_key(ec.SECP256R1()),
        shared_secret=shared_secret,
        ecdh_key_uri="kms://test/ecdhe/1",
        kms_cluster="kms-a.wbx2.com",
        created_at=time.time(),
    )
    key = {
        "uri": "kms://test/keys/1",
        "jwk": {"kty": "oct", "k": b64url(os.urandom(32)), "kid": "kid-1"},
    }
    # Wrap a KMS key response with the shared ECDH secret.
    wrapped = wrap_with_shared_secret(
        json.dumps({"status": 200, "key": key}).encode(), shared_secret
    )

    # Act by processing the KMS response as if it arrived from Mercury.
    encryption.process_kms_messages([wrapped])

    # Assert the key is available in the cache.
    assert encryption._key_cache["kms://test/keys/1"].jwk.kid == "kid-1"


@pytest.mark.asyncio
async def test_decrypt_text_with_cached_key() -> None:
    """Verify text decryption uses a cached KMS key.

    :returns: None.
    """
    # Arrange cached key material and matching ciphertext.
    client = WebexClient("test-token")
    raw_key = os.urandom(32)
    key_uri = "kms://test/keys/msg"
    client.encryption.cache_key(Key(uri=key_uri, jwk=JWK(kty="oct", k=b64url(raw_key))))
    ciphertext = wrap_with_shared_secret(b"hello from webex", raw_key)

    # Act and assert the decrypted plaintext is returned.
    assert await client.encryption.decrypt_text(key_uri, ciphertext) == "hello from webex"
    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_key_synchronous_kms_response() -> None:
    """Verify synchronous HTTP KMS responses return retrieved keys.

    :returns: None.
    """
    # Arrange a client with pre-established ECDH context and mocked KMS endpoint.
    client = WebexClient("test-token", Config())
    encryption = client.encryption
    shared_secret = os.urandom(32)
    encryption.set_device_info("https://device-url", "user-123")
    encryption._ecdh_context = ECDHContext(
        local_private_key=ec.generate_private_key(ec.SECP256R1()),
        shared_secret=shared_secret,
        ecdh_key_uri="kms://test/ecdhe/1",
        kms_cluster="kms-a.wbx2.com",
        created_at=time.time(),
    )
    key = {
        "uri": "kms://ciscospark.com/keys/sync",
        "jwk": {"kty": "oct", "k": b64url(os.urandom(32)), "kid": "sync"},
    }
    response_jwe = wrap_with_shared_secret(
        json.dumps({"status": 200, "key": key}).encode(), shared_secret
    )
    respx.post(re.compile(r"https://encryption-a\.wbx2\.com/encryption/api/v1/kms/messages")).mock(
        return_value=httpx.Response(200, json={"kmsMessages": [response_jwe]})
    )

    # Act by retrieving the key over the synchronous response path.
    result = await encryption.get_key("kms://ciscospark.com/keys/sync")

    # Assert the returned key matches the KMS response payload.
    assert result.uri == "kms://ciscospark.com/keys/sync"
    assert result.jwk.kid == "sync"
    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_get_key_async_mercury_response() -> None:
    """Verify async Mercury KMS responses complete pending key retrieval.

    :returns: None.
    """
    # Arrange a client where the KMS HTTP endpoint accepts async delivery.
    client = WebexClient("test-token", Config(kms_response_timeout=1.0))
    encryption = client.encryption
    shared_secret = os.urandom(32)
    encryption.set_device_info("https://device-url", "user-123")
    encryption._ecdh_context = ECDHContext(
        local_private_key=ec.generate_private_key(ec.SECP256R1()),
        shared_secret=shared_secret,
        ecdh_key_uri="kms://test/ecdhe/1",
        kms_cluster="kms-a.wbx2.com",
        created_at=time.time(),
    )
    respx.post(re.compile(r"https://encryption-a\.wbx2\.com/encryption/api/v1/kms/messages")).mock(
        return_value=httpx.Response(202)
    )

    # Act by starting key retrieval and waiting until a pending request is registered.
    task = asyncio.create_task(encryption.get_key("kms://ciscospark.com/keys/async"))
    for _ in range(50):
        if encryption._pending_requests:
            break
        await asyncio.sleep(0.01)
    request_id = next(iter(encryption._pending_requests))
    key = {
        "uri": "kms://ciscospark.com/keys/async",
        "jwk": {"kty": "oct", "k": b64url(os.urandom(32)), "kid": "async"},
    }
    message = {"status": 200, "requestId": request_id, "key": key}
    wrapped = wrap_with_shared_secret(json.dumps(message).encode(), shared_secret)

    # Complete the pending request through the Mercury message processor.
    encryption.process_kms_messages([wrapped])

    # Assert the retrieval task resolves with the asynchronously delivered key.
    result = await task
    assert result.jwk.kid == "async"
    await client.aclose()


def test_generate_request_id_is_unique() -> None:
    """Verify generated KMS request IDs are not reused.

    :returns: None.
    """
    # Assert two random request IDs differ.
    assert generate_request_id() != generate_request_id()
