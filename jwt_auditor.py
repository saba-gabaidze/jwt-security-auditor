#!/usr/bin/env python3

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import sys

DEFAULT_SECRETS = [
    "secret",
    "secret1",
    "123456",
    "password",
    "admin",
    "jwt",
    "key",
    "master",
    "app_secret",
    "developer",
]


def base64url_decode(input_str: str) -> bytes:
  rem = len(input_str) % 4
  if rem > 0:
    input_str += "=" * (4 - rem)
  return base64.urlsafe_b64decode(input_str)


def parse_jwt(token: str) -> dict:
  parts = token.strip().split(".")
  if len(parts) != 3:
    raise ValueError(
        "Invalid JWT structure. Expected 3 dot-separated parts "
        "(Header.Payload.Signature)."
    )

  header_raw = base64url_decode(parts[0])
  payload_raw = base64url_decode(parts[1])

  header = json.loads(header_raw.decode("utf-8"))
  payload = json.loads(payload_raw.decode("utf-8"))
  signature_b64 = parts[2]

  return {
      "header_b64": parts[0],
      "payload_b64": parts[1],
      "signature_b64": signature_b64,
      "header": header,
      "payload": payload,
  }


def audit_jwt(parsed_jwt: dict, wordlist: list = None) -> list:
  
  findings = []
  header = parsed_jwt["header"]
  payload = parsed_jwt["payload"]
  alg = header.get("alg", "").strip()
  alg_upper = alg.upper()
  already_none = not alg or alg.lower() == "none"


  if already_none:
    findings.append({
        "category": "AUTOMATED",
        "severity": "CRITICAL",
        "title": "Unsigned  Algorithm 'none' Detected",
        "detail": (
            "alg is 'none' or missing  server may skip signature"
            " verification entirely and trust the payload asis."
        ),
    })
  elif alg_upper.startswith("HS"):
    findings.append({
        "category": "AUTOMATED",
        "severity": "INFO",
        "title": f"Symmetric Algorithm ({alg})",
        "detail": (
            "HMAC-signed (shared secret)  crackable offline if the"
            " secret is weak."
        ),
    })
  elif alg_upper.startswith(("RS", "ES", "PS")):
    findings.append({
        "category": "AUTOMATED",
        "severity": "INFO",
        "title": f"Asymmetric Algorithm ({alg})  Confusion Risk",
        "detail": (
            "Asymmetric (pubkey/privkey)  vulnerable to algorithm"
            " confusion if verify() trusts the client-supplied 'alg'"
            " header blindly. See MANUAL TESTS below."
        ),
    })

  kid = header.get("kid", "")

  if "jwk" in header:
    findings.append({
        "category": "AUTOMATED",
        "severity": "INFO",
        "title": "Embedded JWK Header Present",
        "detail": (
            "Token already carries its own pubkey via 'jwk'  confirm"
            " the backend checks key trust, not just signature validity."
        ),
    })

  if "jku" in header:
    findings.append({
        "category": "AUTOMATED",
        "severity": "INFO",
        "title": "External JWK URL ('jku') Header Present",
        "detail": (
            f"Token points to an external keyset at: {header.get('jku')}"
            "  confirm the backend restricts 'jku' to a trusted"
            " domain allowlist."
        ),
    })

  if "exp" in payload:
    try:
      exp_time = datetime.datetime.fromtimestamp(
          payload["exp"], tz=datetime.timezone.utc
      )
      now = datetime.datetime.now(tz=datetime.timezone.utc)
      if now > exp_time:
        findings.append({
            "category": "AUTOMATED",
            "severity": "INFO",
            "title": "Expired Token",
            "detail": (
                f"Expired at"
                f" {exp_time.strftime('%Y-%m-%d %H:%M:%S UTC')}."
            ),
        })
    except Exception:
      pass
  else:
    findings.append({
        "category": "AUTOMATED",
        "severity": "LOW",
        "title": "Missing Expiration Claim ('exp')",
        "detail": (
            "No 'exp' claim  token never expires unless explicitly"
            " revoked server-side."
        ),
    })

  if alg_upper == "HS256" and parsed_jwt["signature_b64"]:
    secrets_to_test = wordlist if wordlist else DEFAULT_SECRETS
    message = (
        f"{parsed_jwt['header_b64']}.{parsed_jwt['payload_b64']}".encode(
            "utf-8"
        )
    )
    actual_sig = base64url_decode(parsed_jwt["signature_b64"])

    cracked_secret = None
    for secret in secrets_to_test:
      candidate_sig = hmac.new(
          secret.encode("utf-8"), message, hashlib.sha256
      ).digest()
      if hmac.compare_digest(candidate_sig, actual_sig):
        cracked_secret = secret
        break

    if cracked_secret:
      findings.append({
          "category": "AUTOMATED",
          "severity": "CRITICAL",
          "title": "Weak HMAC Secret Recovered",
          "detail": (
              f"Signature forged using secret '{cracked_secret}' "
              " you can now sign arbitrary tokens."
          ),
      })
    else:
      findings.append({
          "category": "AUTOMATED",
          "severity": "INFO",
          "title": "HS256 Secret Not Cracked",
          "detail": (
              f"Tried {len(secrets_to_test)} candidate secret(s), no"
              " match → retry with -w <bigger wordlist>, or Hashcat"
              " (-a 0 -m 16500) for serious offline cracking."
          ),
      })

  # ------------------------------------------------------------------
  # MANUAL
  # ------------------------------------------------------------------

  findings.append({
      "category": "MANUAL",
      "title": "Signature-Not-Verified Check",
      "detail": (
          "Tamper the payload (e.g. sub → administrator), keep the"
          " ORIGINAL signature, resend → some backends decode the"
          " payload without ever calling verify()."
      ),
  })

  findings.append({
      "category": "MANUAL",
      "title": "'alg: none' Forgery",
      "detail": (
          "Set alg=none (or drop it), strip the signature but keep the"
          " trailing dot (Header.Payload.) → resend."
      ),
  })

  if alg_upper.startswith(("RS", "ES", "PS")):
    findings.append({
        "category": "MANUAL",
        "title": "JWK Embedding Attack",
        "detail": (
            "Generate a rogue RSA/EC keypair → embed the pubkey in"
            " the token's own 'jwk' header → sign with your privkey"
            " → resend. Works if the server trusts any key the"
            " token brings with it."
        ),
    })
    findings.append({
        "category": "MANUAL",
        "title": "JKU Header Injection",
        "detail": (
            "Generate a rogue keypair → host the pubkey as a JWKS on"
            " a server you control → point 'jku' at it, match 'kid'"
            " → sign → resend. Works if 'jku' isn't"
            " domain-restricted."
        ),
    })
    if alg_upper == "RS256":
      findings.append({
          "category": "MANUAL",
          "title": "RS256 → HS256 Algorithm Confusion",
          "detail": (
              "Get the server's pubkey (/jwks.json or"
              " /.well-known/jwks.json) → PEM → Base64 →"
              " alg=HS256 → sign using that string as the HMAC"
              " secret."
          ),
      })
      findings.append({
          "category": "MANUAL",
          "title": "Public Key Derivation (sig2n)",
          "detail": (
              "No exposed pubkey? Capture 2 tokens signed with the same"
              " key → docker run --rm -it portswigger/sig2n"
              " <token1> <token2> → derive candidate pubkeys →"
              " feed each into the RS256→HS256 attack above."
          ),
      })

  if kid:
    findings.append({
        "category": "MANUAL",
        "title": "'kid' Path Traversal / Injection",
        "detail": (
            f"'kid' present (value: '{kid}') → if used in a file"
            " lookup, try '../../../../../../../dev/null' paired with"
            " an empty symmetric key \"k\":\"\" → if used in a DB"
            " lookup instead, try SQL injection."
        ),
    })

  return findings


def generate_report(parsed_jwt: dict, findings: list) -> None:
  """Prints a two-section report: AUTOMATED findings, then MANUAL tests."""
  automated = [f for f in findings if f["category"] == "AUTOMATED"]
  manual = [f for f in findings if f["category"] == "MANUAL"]

  print("\n" + "=" * 64)
  print("              JWT SECURITY INSPECTION REPORT")
  print("=" * 64)

  print("\n[+] DECODED HEADER:")
  print(json.dumps(parsed_jwt["header"], indent=2))

  print("\n[+] DECODED PAYLOAD:")
  print(json.dumps(parsed_jwt["payload"], indent=2))

  print("\n" + "-" * 64)
  print("AUTOMATED FINDINGS (verified against this exact token)")
  print("-" * 64)
  if not automated:
    print("  [–] Nothing to report.")
  else:
    for f in automated:
      sev = f["severity"]
      print(f"  [{sev:<8}] {f['title']}")
      print(f"             {f['detail']}\n")

  print("-" * 64)
  print("RECOMMENDED MANUAL TESTS (applicable based on token structure)")
  print("-" * 64)
  if not manual:
    print("  [–] No applicable manual tests identified.")
  else:
    for f in manual:
      print(f"  [TEST]    {f['title']}")
      print(f"            {f['detail']}\n")

  print("=" * 64 + "\n")


def main() -> None:
  """CLI entry point: parse args, run the audit, print the report."""
  parser = argparse.ArgumentParser(
      description=(
          "Offline JWT security auditor & manual-test checklist generator"
      )
  )
  parser.add_argument("jwt", help="Raw JWT string (Header.Payload.Signature)")
  parser.add_argument(
      "-w",
      "--wordlist",
      help="Path to custom dictionary file for HS256 secret cracking",
  )

  args = parser.parse_args()

  wordlist = None
  if args.wordlist:
    try:
      with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
        wordlist = [line.strip() for line in f if line.strip()]
    except Exception as e:
      print(f"[-] Error reading wordlist file: {e}")
      sys.exit(1)

  try:
    parsed = parse_jwt(args.jwt)
    findings = audit_jwt(parsed, wordlist)
    generate_report(parsed, findings)
  except Exception as e:
    print(f"[-] Error inspecting JWT: {e}")
    sys.exit(1)


if __name__ == "__main__":
  main()
