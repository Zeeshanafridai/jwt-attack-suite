import base64
import json
import hmac
import hashlib
import struct
import time


def b64url_decode(data: str) -> bytes:
    data += "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_token(token: str) -> tuple:
    """Decode JWT without verification. Returns (header, payload, signature, raw_parts)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format — expected 3 parts")
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        signature = b64url_decode(parts[2])
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")
    return header, payload, signature, parts


def encode_token(header: dict, payload: dict, signature: bytes = b"") -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    s = b64url_encode(signature)
    return f"{h}.{p}.{s}"


def sign_hs256(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def sign_hs384(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha384).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def sign_hs512(header: dict, payload: dict, secret: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha512).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def pretty_print_token(token: str):
    try:
        header, payload, sig, parts = decode_token(token)
        print("\n  ┌─ HEADER")
        for k, v in header.items():
            print(f"  │  {k}: {v}")
        print("  ├─ PAYLOAD")
        for k, v in payload.items():
            if k in ("exp", "iat", "nbf"):
                try:
                    human = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(int(v)))
                    print(f"  │  {k}: {v}  ({human})")
                    continue
                except Exception:
                    pass
            print(f"  │  {k}: {v}")
        print(f"  └─ SIGNATURE: {parts[2][:32]}...")
    except Exception as e:
        print(f"  [!] Could not pretty-print token: {e}")
