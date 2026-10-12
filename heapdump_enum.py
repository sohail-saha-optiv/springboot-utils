#!/usr/bin/env python3
"""
heapdump_enum.py — self-contained, everything-grade secret & IOC extractor for
Java HPROF heapdumps (and any binary blob). No external tools, no dependencies,
fully client-agnostic: company targeting comes from --company-domain at runtime.

  python3 heapdump_enum.py <heapdump> -o <outdir> [--company-domain DOM]...
                           [--min-len N] [--no-utf16] [--chunk-mb N]
                           [--pattern NAME=REGEX]...

How it works
------------
Streams the file in chunks (progress on STDOUT) and extracts ASCII/Latin-1
runs (JDK9+ compact strings), UTF-16BE char[] (JDK8), UTF-16LE (paranoia),
plus full multi-line PEM/PGP private-key blocks straight off the raw bytes.

For each --company-domain DOM (repeatable, substring semantics — e.g.
"example.com" also matches "prod.example.com:9090/x"), a runtime-built pattern
bucket company_<dom> captures every string containing that domain — bare
hostnames, URLs, anything. That replaces any hardcoded target list.

Every bucket records the RAW secret; where a processed form exists it is shown
alongside (JWT -> decoded claims, Basic -> user:pass, credential-URI ->
scheme/user/pass/host, base64-looking value -> decoded-when-printable).

Buckets (loot/<name>.txt) — see PATTERNS. Plus: pem_blocks, urls_internal,
company_<dom>, high_entropy, custom_<name>.

OPSEC: never upload heapdumps to online analyzers — they hold live secrets.
"""
import argparse
import base64
import json
import re
import sys
import time
from pathlib import Path

# ------------------------------------------------------------- pattern set --
PATTERNS = {
    # --- identity / tokens ---
    "jwt":             rb"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{3,}\b",
    "okta_client_ids": rb"\b0oa[a-zA-Z0-9]{17}\b",
    "okta_ssws":       rb"\b00[a-zA-Z0-9_\-]{38,42}\b",
    "gcp_oauth":       rb"\bya29\.[0-9A-Za-z_\-]{20,}\b",
    "facebook":        rb"\bEAACEdEose0cBA[0-9A-Za-z]+\b",
    # --- cloud ---
    "aws_keys":        rb"\bAKIA[0-9A-Z]{16}\b",
    "aws_session":     rb"\b(?:ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
    "aws_arns":        rb"\barn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d{0,12}:[^\s\"'<>\]}]+",
    "gcp_keys":        rb"\bAIza[0-9A-Za-z_\-]{35}\b",
    "gcp_svc_acct":    rb"\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b",
    "gcp_svc_json":    rb"\"type\"\s*:\s*\"service_account\"",
    "azure_connstr":   rb"DefaultEndpointsProtocol=https?;[^\s\"']{0,200}?(?:AccountKey|SharedAccessKey)=[^\s\"';]{10,}",
    "azure_sas":       rb"[?&]sig=[A-Za-z0-9+/=%]{20,}",
    "ado_connstr":     rb"(?i)\bServer=[^\s;\"']+;[^\"']{0,120}?(?:User Id|UID)=[^;\"']+;[^\"']{0,60}?Password=[^;\"']+",
    # --- vcs / ci / registries ---
    "github":          rb"\b(?:gh[opsur]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
    "gitlab":          rb"\bgl(?:pat|dt)-[A-Za-z0-9\-_]{20,}\b",
    "npm":             rb"\bnpm_[A-Za-z0-9]{36}\b",
    "pypi":            rb"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{30,}\b",
    "docker_auths":    rb"\"auths\"\s*:\s*\{[^}]{0,400}?\"auth\"\s*:\s*\"[A-Za-z0-9+/=]{8,}\"",
    "k8s_secret":      rb"\bkind:\s*Secret\b",
    "vault":           rb"\bhv[sb]\.[A-Za-z0-9_\-]{20,}\b",
    # --- saas / ai ---
    "slack":           rb"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b|\bxapp-[A-Za-z0-9\-]{10,}\b",
    "stripe":          rb"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",
    "sendgrid":        rb"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    "twilio":          rb"\b(?:SK|AC)[0-9a-f]{32}\b",
    "openai":          rb"\bsk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{10,}\b|\bsk-proj-[A-Za-z0-9_\-]{30,}\b",
    "anthropic":       rb"\bsk-ant-[A-Za-z0-9_\-]{30,}\b",
    "huggingface":     rb"\bhf_[A-Za-z0-9]{30,}\b",
    "mailgun":         rb"\bkey-[0-9a-f]{32}\b",
    "square":          rb"\bsq0[ac][st]p-[A-Za-z0-9_\-]{20,}\b",
    "shopify":         rb"\bshp(?:at|ss|ca|pa)_[0-9a-f]{32}\b",
    "braintree":       rb"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
    # --- crypto material ---
    "ssh_keys":        rb"\bssh-(?:rsa|ed25519|dss)\s+AAAA[A-Za-z0-9+/=]{40,}",
    "jwk_private":     rb"\"kty\"\s*:\s*\"(?:RSA|EC|OKP|oct)\"[^}]{0,200}?\"(?:d|k)\"\s*:\s*\"[A-Za-z0-9_\-]{20,}\"",
    "bcrypt":          rb"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}",
    # --- auth headers / sessions / cookies ---
    "auth_headers":    rb"(?i)\bAuthorization:\s*(?:Basic|Bearer|Digest|Negotiate|Token|ApiKey)\s+\S+|"
                       rb"\b(?:Basic\s+[A-Za-z0-9+/=]{12,}|Bearer\s+(?!eyJ)[A-Za-z0-9._~+/\-]{8,})",
    "session_tokens":  rb"(?i)\b(?:JSESSIONID|SESSIONID|SESSION|PHPSESSID|session[-_]?id|session[-_]?token|auth[-_]?token|sso[-_]?token|remember[-_]?me)\s*[:=]\s*[\"']?[A-Za-z0-9._~+/\-]{8,}",
    "cookies":         rb"(?i)\bCookie:\s*[A-Za-z0-9_\-.]+=[^\s;]{3,}",
    "api_key_headers": rb"(?i)\bX-[A-Za-z0-9\-]*API[-_ ]?Key\s*[:=]\s*[\"']?\S{6,}",
    # --- URIs / infra ---
    "cred_uris":       rb"\b[a-z][a-z0-9+.\-]*://[^/\s:@]{0,64}:[^@\s\"']{1,128}@[^\s\"']{3,}",
    "jdbc_ldap":       rb"\b(?:jdbc:[a-z0-9]+:[^\s\"'<>\]}]{5,}|ldaps?://[^\s\"'<>\]}]+)",
    "urls":            rb"\bhttps?://[^\s\"'<>\]}]+",
    "ipv4":            rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    # --- secrets by name ---
    "passwords": (rb"(?i)(?:passw(?:or)?d|pwd|secret|token|credential|api[-_. ]?key"
                  rb"|access[-_. ]?key|secret[-_. ]?key|private[-_. ]?key|client[-_. ]?secret"
                  rb"|auth[-_. ]?key|session[-_. ]?key|signing[-_. ]?key|master[-_. ]?key"
                  rb"|encryption[-_. ]?key|passphrase|salt|pin)s?[\"']?\s*[:=]\s*[\"']?[^\s\"',}\]]{3,150}"),
    "emails":          rb"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
    "hex40":           rb"\b[0-9a-fA-F]{40,}\b",
    "hex32":           rb"\b[0-9a-f]{32}\b",
    "hex64":           rb"\b[0-9a-fA-F]{64}\b",
}
PEM_RX = (rb"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY(?: BLOCK)?-----.*?"
          rb"-----END (?:[A-Z0-9 ]* )?PRIVATE KEY(?: BLOCK)?-----")

# generic internal markers (company-specific ones come from --company-domain)
GENERIC_INTERNAL = ("localhost", "127.", "10.", "192.168.", ".local", ".internal",
                    ".lan", ".corp", ".intranet")
RFC172 = re.compile(r"\b172\.(?:1[6-9]|2\d|3[01])\.")

FILENAMES = {"jwt": "jwts_raw.txt"}
CHUNK_OVERLAP = 65536  # covers multi-KB PEM blocks / long strings across chunks

# ---------------------------------------------------------------- helpers ---
def b64url(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt(tok):
    try:
        p = tok.split(".")
        return json.loads(b64url(p[0])), json.loads(b64url(p[1]))
    except Exception:  # noqa: BLE001
        return None, None


def try_b64(s):
    """processed form for base64-looking values."""
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]{8,}", s) or len(s) % 4 == 1:
        return None
    for dec in (lambda: base64.b64decode(s), lambda: base64.urlsafe_b64decode(s)):
        try:
            txt = dec().decode("utf-8")
            if txt and all(32 <= ord(c) < 127 or c == "\t" for c in txt):
                return txt
        except Exception:  # noqa: BLE001
            continue
    return None


def process(bucket, val):
    """-> processed string or None. raw is always kept separately."""
    try:
        if bucket == "jwt":
            _, pay = decode_jwt(val)
            if pay:
                return (f"iss={pay.get('iss')} aud={pay.get('aud')} scp={pay.get('scp')} "
                        f"cid={pay.get('cid', pay.get('sub'))} exp={pay.get('exp')}")
        if bucket == "auth_headers" and "Basic " in val:
            raw = val.split("Basic ", 1)[1].split()[0]
            return f"user:pass = {base64.b64decode(raw).decode('utf-8', 'replace')}"
        if bucket == "cred_uris":
            m = re.match(r"([a-z][a-z0-9+.\-]*)://([^:/]*):([^@]+)@(.+)", val)
            if m:
                return (f"scheme={m.group(1)} user={m.group(2) or '(empty)'} "
                        f"password={m.group(3)} host={m.group(4)}")
        if bucket == "passwords":
            v = re.split(r"[:=]", val, maxsplit=1)[1].strip().strip("\"'")
            dec = try_b64(v)
            if dec and dec != v:
                return f"base64-decoded = {dec}"
    except Exception:  # noqa: BLE001
        return None
    return None


def entropy_ok(s):
    if not (32 <= len(s) <= 128):
        return False
    if not re.fullmatch(r"[A-Za-z0-9+/=_\-]+", s):
        return False
    return sum(bool(re.search(c, s)) for c in (r"[a-z]", r"[A-Z]", r"\d")) >= 3


def is_internal(url, company_domains):
    low = url.lower()
    if any(d.lower() in low for d in company_domains):
        return True
    return any(m in low for m in GENERIC_INTERNAL) or bool(RFC172.search(url))

# ------------------------------------------------------------------- main ---
def main():
    ap = argparse.ArgumentParser(
        description="everything-grade HPROF/binary secret extractor (self-contained, "
                    "client-agnostic)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("dump",
                    help="path to the heapdump file (or any binary) to scan")
    ap.add_argument("-o", "--out", required=True, metavar="DIR",
                    help="output DIRECTORY — created if missing; receives summary.md "
                         "plus loot/<category>.txt files")
    ap.add_argument("--company-domain", action="append", default=[], metavar="DOM",
                    help="company domain substring, repeatable (e.g. --company-domain "
                         "example.com). Drives: (a) internal-URL classification, (b) a "
                         "runtime-built 'company_<dom>' bucket catching every string "
                         "containing the domain — bare hostnames included")
    ap.add_argument("--min-len", type=int, default=8,
                    help="minimum string length to extract (default 8)")
    ap.add_argument("--no-utf16", action="store_true",
                    help="skip UTF-16BE/LE string extraction (faster; loses JDK8 "
                         "char[] strings)")
    ap.add_argument("--chunk-mb", type=int, default=32,
                    help="read chunk size in MB (default 32; 64KB overlap keeps "
                         "PEM blocks/long strings intact across boundaries)")
    ap.add_argument("--pattern", action="append", default=[], metavar="NAME=REGEX",
                    help="custom bytes-regex bucket, repeatable; results land in "
                         "loot/NAME.txt")
    args = ap.parse_args()

    patterns = dict(PATTERNS)
    for spec in args.pattern:
        if "=" not in spec:
            ap.error(f"--pattern must be NAME=REGEX (got {spec!r})")
        name, rx = spec.split("=", 1)
        patterns[f"custom_{name}"] = rx.encode()

    # runtime-built company patterns — replace any hardcoded target list
    company_domains = [d.strip().lstrip(".") for d in args.company_domain if d.strip()]
    for dom in company_domains:
        esc = re.escape(dom).encode()
        patterns[f"company_{dom.replace('.', '_')}"] = (
            rb"(?:[A-Za-z0-9_\-]+\.)*" + esc + rb"(?::\d{1,5})?"
            rb"(?:/[^\s\"'<>\]}]*)?")

    compiled = {k: re.compile(v) for k, v in patterns.items()}
    path = Path(args.dump)
    out = Path(args.out)
    loot = out / "loot"
    loot.mkdir(parents=True, exist_ok=True)
    total = path.stat().st_size
    chunk = args.chunk_mb * 1024 * 1024

    ascii_rx = re.compile(rb"[\x20-\x7e]{%d,}" % args.min_len)
    be_rx = re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % args.min_len)
    le_rx = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % args.min_len)

    hits = {k: set() for k in compiled}
    pems = set()
    seen = set()
    n_strings = 0
    t0 = time.time()

    print(f"[*] {path} — {total/1e6:.1f} MB, chunk={args.chunk_mb} MB, "
          f"{len(compiled)} pattern buckets, company domains: {company_domains or 'none'}",
          flush=True)
    with open(path, "rb") as fh:
        off = 0
        ci = 0
        n_chunks = max(1, -(-total // chunk))
        while True:
            data = fh.read(chunk)
            if not data:
                break
            ci += 1
            for m in re.finditer(PEM_RX, data, re.DOTALL):
                pems.add(m.group(0).decode("latin-1"))
            for m in ascii_rx.finditer(data):
                s = m.group(0).decode("latin-1")
                if s not in seen:
                    seen.add(s)
                    n_strings += 1
                    lb = m.group(0)
                    for k, rx in compiled.items():
                        for mm in rx.finditer(lb):
                            hits[k].add(mm.group(0).decode("latin-1"))
            if not args.no_utf16:
                for rx, enc in ((be_rx, "utf-16-be"), (le_rx, "utf-16-le")):
                    for m in rx.finditer(data):
                        try:
                            s = m.group(0).decode(enc).strip()
                        except Exception:  # noqa: BLE001
                            continue
                        if len(s) >= args.min_len and s not in seen:
                            seen.add(s)
                            n_strings += 1
                            lb = s.encode("latin-1", "replace")
                            for k, crx in compiled.items():
                                for mm in crx.finditer(lb):
                                    hits[k].add(mm.group(0).decode("latin-1"))
            fh.seek(off + chunk - CHUNK_OVERLAP if off + chunk < total else off + chunk)
            off = fh.tell()
            pct = min(100.0, off / total * 100)
            print(f"[*] chunk {ci}/{n_chunks} {pct:5.1f}% | {off/1e6:.0f} MB in "
                  f"{time.time()-t0:.0f}s | strings {n_strings:,} | "
                  f"hits {sum(len(v) for v in hits.values()) + len(pems):,}", flush=True)
            if off >= total:
                break

    hits["pem_blocks"] = pems
    n_hits = sum(len(v) for v in hits.values())
    print(f"[*] extraction done: {n_strings:,} unique strings, {n_hits:,} raw hits "
          f"({time.time()-t0:.0f}s). Processing…", flush=True)

    he = {s for s in seen if entropy_ok(s)} - set().union(*hits.values())
    hits["high_entropy"] = he

    i = 0
    for k, vals in hits.items():
        i += 1
        fn = FILENAMES.get(k, f"{k}.txt")
        with open(loot / fn, "w") as fh:
            for v in sorted(vals):
                proc = process(k, v)
                fh.write(v + (f"    ==> {proc}" if proc else "") + "\n")
        print(f"[*] wrote loot/{fn} ({len(vals)} entries)  [{i}/{len(hits)}]", flush=True)

    urls = hits.get("urls", set())
    internal = sorted(u for u in urls if is_internal(u, company_domains))
    with open(loot / "urls_internal.txt", "w") as fh:
        fh.write("\n".join(internal) + ("\n" if internal else ""))

    now = int(time.time())
    rows = []
    for tok in hits["jwt"]:
        _, pay = decode_jwt(tok)
        if pay:
            exp = int(pay.get("exp", 0) or 0)
            rows.append(("LIVE" if exp > now else "EXPIRED", pay.get("iss", "?"),
                         str(pay.get("aud", "?")), str(pay.get("scp", "")),
                         str(pay.get("cid", pay.get("sub", "?"))), exp, tok))
    rows.sort(key=lambda r: (r[0] != "LIVE", r[1], r[2]))
    with open(loot / "jwts.txt", "w") as fh:
        for r in rows:
            fh.write(f"[{r[0]}] iss={r[1]} aud={r[2]} scp={r[3]} cid={r[4]} "
                     f"exp={r[5]}\n{r[6]}\n\n")

    live = [r for r in rows if r[0] == "LIVE"]
    s = [f"# heapdump extraction summary — {path.name}", ""]
    s.append(f"- bytes: {total:,} | strings: {n_strings:,} | raw hits: {n_hits:,} | "
             f"runtime: {time.time()-t0:.0f}s")
    s.append(f"- company domains: {company_domains or 'none given'}")
    for k in hits:
        s.append(f"- {k}: {len(hits[k])} unique")
    s.append(f"- internal URLs: {len(internal)}")
    s.append(f"- JWTs decoded: {len(rows)}  (**LIVE: {len(live)}**)")
    if live:
        s += ["", "## LIVE tokens"]
        s += [f"- iss={r[1]} aud={r[2]} scp={r[3]} cid={r[4]}" for r in live]
    if internal:
        s += ["", f"## internal URLs ({len(internal)})"]
        s += [f"- {u}" for u in internal]
    (out / "summary.md").write_text("\n".join(s) + "\n")

    print(f"\n[+] DONE -> {out/'summary.md'}", flush=True)
    print(f"[+] JWTs {len(rows)} ({len(live)} LIVE) | AWS {len(hits['aws_keys'])} | "
          f"PEM {len(pems)} | cred-URIs {len(hits['cred_uris'])} | "
          f"passwords {len(hits['passwords'])} | internal URLs {len(internal)}", flush=True)


if __name__ == "__main__":
    main()
