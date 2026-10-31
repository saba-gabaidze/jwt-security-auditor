# jwt-security-auditor

Offline Python CLI tool to inspect, audit, and generate manual test checklists for JSON Web Tokens.

## What it does

Parses a JWT with no network calls and splits results into two parts:

 **Automated findings** — things actually verified about the token: a crackable HMAC secret, an already-expired token, `alg: none`.
 **Manual test checklist** — attack classes the token's algorithm and headers make possible (JWK embedding, JKU injection, RS256 to HS256 confusion, kid traversal), generated from the token's structure

## Usage

python3 jwt_auditor.py “<jwt>“
python3 jwt_auditor.py “<jwt>“ -w wordlist.txt


`-w` points to a custom wordlist for the offline HS256 brute-force. Without it, a small built-in list of common weak secrets is used.

## How the checks work

- `alg: HS256` → tries an offline HMAC dictionary attack against the signature.
- `alg: RS256 / ES256 / PS256` → flags algorithm confusion risk, lists JWK embedding, JKU hosting, RS256 to HS256 forgery, and sig2n key derivation as manual tests.
- `kid` present → flags path traversal / SQL injection as worth testing.
- `exp` → checked for expiry, flagged if missing entirely.

## Limitations

This tool never contacts the target server. Signature-not-verified bypass and public key derivation (sig2n) require live interaction with the server and can't be checked offline  they're listed as manual tests, not automated findings.

## Requirements

Python 3, standard library only. No dependencies to install.
