#!/usr/bin/env python3
"""
login.py — Facebook Login (www.facebook.com)
═══════════════════════════════════════════════════════════════════════════════
Full 3-step login algorithm with verified token extraction.
Saves authenticated cookies to fb_session.json.

ALGORITHM:
  Step 1 ─ GET https://www.facebook.com/
              Seeds required device cookies: datr, sb, fr
              Retries until datr is confirmed (critical for auth)

  Step 2 ─ GET https://www.facebook.com/login/
              Extracts ALL hidden form fields dynamically:
                lsd, jazoest, next, login_source, lwv
              Reads form action URL from the actual HTML (never hardcoded)
              Recomputes jazoest: "2" + str(sum(ord(c) for c in lsd))

  Step 3 ─ POST to form action URL with credentials + all tokens
              Follows all redirects
              Checks c_user + xs cookies → definitive proof of auth

  Errors ─ Classified by redirect URL patterns:
              /login/?err=29         → wrong password
              /checkpoint/           → 2FA / suspicious login
              /login/identify/       → account not found

Usage:
    python3 login.py                     # interactive (recommended)
    python3 login.py -e EMAIL            # prompts for password only
    python3 login.py -e EMAIL -p PASS    # fully automated
    python3 login.py --check             # verify saved session is valid

Requirements:
    pip install requests beautifulsoup4
"""

import argparse
import getpass
import json
import re
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

# ── Constants ──────────────────────────────────────────────────────────────────
SESSION_FILE = Path("fb_session.json")
DEBUG_FILE   = Path("login_debug.html")

BASE      = "https://www.facebook.com"
URL_HOME  = "https://www.facebook.com/"
URL_LOGIN = "https://www.facebook.com/login/"

# Desktop Chrome 124 on Windows — www.facebook.com serves correct layout for this UA
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Full realistic browser headers — Facebook fingerprints these strictly
HEADERS = {
    "User-Agent":                USER_AGENT,
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-CH-UA":                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile":          "?0",
    "Sec-CH-UA-Platform":        '"Windows"',
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Sec-Fetch-User":            "?1",
    "DNT":                       "1",
}

# ANSI colours
RST = "\033[0m"
GRN = "\033[92m"
YLW = "\033[93m"
RED = "\033[91m"
CYN = "\033[96m"
DIM = "\033[2m"
BLD = "\033[1m"
MAG = "\033[95m"


# ══════════════════════════════════════════════════════════════════════════════
# CORE: JAZOEST ALGORITHM
# Reverse-engineered from Facebook's obfuscated JS bundle:
#   var n = 0;
#   for (var i = 0; i < token.length; i++) { n += token.charCodeAt(i); }
#   return "2" + String(n);
# We ALWAYS recompute — never trust the value already in the page HTML.
# ══════════════════════════════════════════════════════════════════════════════

def compute_jazoest(lsd: str) -> str:
    return "2" + str(sum(ord(ch) for ch in lsd))


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Seed device cookies (datr, sb, fr)
# ══════════════════════════════════════════════════════════════════════════════

def _step1_seed_cookies(session: requests.Session) -> None:
    """
    Visit www.facebook.com to receive device identity cookies.

    datr  = Device Attribution Token — REQUIRED before login POST.
            Facebook CDN sets this on the very first visit.
            Without it Facebook rejects or checkpoints the login.
    sb    = Secure Browser token
    fr    = Advertising/tracking token

    Retries up to 3x if datr not set (regional CDN variance).
    """
    _info("Step 1/3 │ Seeding device cookies (datr, sb, fr) …")

    for attempt in range(1, 4):
        try:
            session.get(
                URL_HOME,
                headers={**HEADERS, "Cache-Control": "no-cache, no-store"},
                timeout=20,
                allow_redirects=True,
            )
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                f"Cannot connect to www.facebook.com.\n"
                f"  Check your internet connection.\n"
                f"  Detail: {e}"
            )
        except requests.exceptions.Timeout:
            raise RuntimeError("Connection to www.facebook.com timed out.")
        except requests.RequestException as e:
            raise RuntimeError(f"Network error in Step 1: {e}")

        datr = session.cookies.get("datr", "")
        sb   = session.cookies.get("sb",   "")
        if datr:
            _dim(f"         datr={datr[:12]}…  sb={'set' if sb else 'not set'}")
            return

        _dim(f"         Attempt {attempt}/3 — datr not received, retrying in 2s …")
        time.sleep(2)

    _dim("         WARNING: datr not confirmed, proceeding (may cause checkpoint)")


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Fetch login page and extract all form tokens
# ══════════════════════════════════════════════════════════════════════════════

def _step2_get_form(session: requests.Session) -> tuple:
    """
    GET the login page and parse every token the POST needs.

    Returns: (action_url: str, fields: dict)

    lsd extraction order:
      1. <input name="lsd" value="..."> inside login form  (normal case)
      2. JSON blob in <script>: "LSD",[],{"token":"AVo..."}  (SPA pages)
      3. JSON blob: "lsd":"AVo..."

    jazoest: always recomputed from actual lsd, never trusted from page.
    action:  always read from form.action, never hardcoded.
    """
    _info("Step 2/3 │ Fetching login page, extracting tokens …")

    try:
        r = session.get(
            URL_LOGIN,
            headers={
                **HEADERS,
                "Referer":        URL_HOME,
                "Sec-Fetch-Site": "same-origin",
            },
            timeout=20,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch login page: {e}")

    html = r.text

    # ── Find the login form ────────────────────────────────────────────────────
    soup = BeautifulSoup(html, "html.parser")
    form = (
        soup.find("form", id="login_form")
        or soup.find("form", attrs={"action": re.compile(r"/login", re.I)})
        or soup.find("form")
    )

    if not form:
        DEBUG_FILE.write_text(html, encoding="utf-8")
        raise RuntimeError(
            "No login form found on the page.\n"
            f"  Debug HTML saved → {DEBUG_FILE}\n"
            "  Likely cause: Facebook is serving a CAPTCHA or blocking this IP."
        )

    # ── Read action URL from form attribute ───────────────────────────────────
    action = (form.get("action") or "").strip()
    if not action:
        action = URL_LOGIN
    elif action.startswith("/"):
        action = BASE + action
    elif not action.startswith("http"):
        action = urljoin(BASE + "/", action)

    # ── Extract all <input> fields ─────────────────────────────────────────────
    fields: dict = {}
    for inp in form.find_all("input"):
        n = inp.get("name", "").strip()
        v = inp.get("value", "")
        if n:
            fields[n] = v

    # ── lsd fallback: search JavaScript blobs ─────────────────────────────────
    lsd = fields.get("lsd", "").strip()
    if not lsd:
        for pat in [
            r'"LSD"\s*,\s*\[\]\s*,\s*\{\s*"token"\s*:\s*"([^"]{4,30})"',
            r'name="lsd"\s+value="([^"]{4,30})"',
            r'"lsd"\s*:\s*"([^"]{4,30})"',
            r'\["LSD"\s*,\s*"([^"]{4,30})"\]',
        ]:
            m = re.search(pat, html)
            if m:
                lsd = m.group(1)
                fields["lsd"] = lsd
                _dim(f"         lsd extracted via JS pattern")
                break

    if not lsd:
        DEBUG_FILE.write_text(html, encoding="utf-8")
        raise RuntimeError(
            "Could not extract lsd CSRF token from login page.\n"
            f"  Debug HTML saved → {DEBUG_FILE}\n"
            "  Facebook may be blocking this request (try a VPN or different network)."
        )

    # ── Recompute jazoest ──────────────────────────────────────────────────────
    fields["jazoest"] = compute_jazoest(lsd)

    _dim(f"         action       = {action}")
    _dim(f"         lsd          = {lsd!r}")
    _dim(f"         jazoest      = {fields['jazoest']!r}  (recomputed from lsd)")
    _dim(f"         login_source = {fields.get('login_source','–')!r}")
    _dim(f"         lwv          = {fields.get('lwv','–')!r}")

    return action, fields


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — POST credentials
# ══════════════════════════════════════════════════════════════════════════════

def _step3_post_login(
    session:  requests.Session,
    action:   str,
    fields:   dict,
    email:    str,
    password: str,
) -> requests.Response:
    """
    Submit the login form with all extracted tokens + credentials.

    Payload includes every hidden field from the form so we don't
    accidentally omit a token Facebook added without notice.
    """
    _info("Step 3/3 │ Submitting credentials …")

    payload = dict(fields)
    payload["email"]  = email
    payload["pass"]   = password
    payload["login"]  = "Log in"
    payload.setdefault("login_source", "comet_headerless_login")
    payload.setdefault("lwv",          "100")
    payload.setdefault("next",         "")

    try:
        r = session.post(
            action,
            data=payload,
            headers={
                **HEADERS,
                "Content-Type":   "application/x-www-form-urlencoded",
                "Origin":         BASE,
                "Referer":        URL_LOGIN,
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-User": "?1",
                "Sec-Fetch-Dest": "document",
                "Cache-Control":  "max-age=0",
            },
            timeout=30,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Network error during login POST: {e}")

    _dim(f"         Final URL: {r.url}")
    _dim(f"         Status:    {r.status_code}")

    return r


# ══════════════════════════════════════════════════════════════════════════════
# AUTH VERIFICATION
# c_user (numeric UID) + xs (session hash) = definitive Facebook auth cookies
# ══════════════════════════════════════════════════════════════════════════════

def _is_authenticated(session: requests.Session) -> bool:
    c_user = str(session.cookies.get("c_user", "")).strip()
    xs     = str(session.cookies.get("xs",     "")).strip()
    return bool(c_user and xs and c_user.isdigit())


# ══════════════════════════════════════════════════════════════════════════════
# ERROR DIAGNOSIS
# ══════════════════════════════════════════════════════════════════════════════

def _diagnose(response: requests.Response) -> str:
    final_url = response.url
    html      = response.text
    low       = html.lower()
    qs        = parse_qs(urlparse(final_url).query)
    err       = qs.get("err", [""])[0]

    # URL-based (most reliable)
    if "checkpoint" in final_url:
        return (
            f"{YLW}CHECKPOINT / 2FA REQUIRED{RST}\n\n"
            "  Facebook flagged this login as suspicious.\n\n"
            "  Fix:\n"
            "    1. Open https://www.facebook.com in a real browser\n"
            "    2. Log in and pass the security check\n"
            "    3. Export cookies with browser extension 'Cookie-Editor'\n"
            '    4. Build fb_session.json:\n'
            '       {\n'
            '         "email": "you@email.com",\n'
            '         "uid": "YOUR_NUMERIC_USER_ID",\n'
            '         "saved_at": "2024-01-01 00:00:00",\n'
            '         "cookies": { <paste exported cookie dict here> }\n'
            '       }\n'
        )

    if "login/identify" in final_url:
        return "No Facebook account found for that email or phone number."

    if err in ("29", "29051"):
        return "Wrong password — please double-check and try again."

    if err == "2":
        return "Account is disabled."

    if err == "56":
        return "Facebook requires identity verification. Complete at https://www.facebook.com"

    if err == "1":
        return f"Facebook error code 1 — possible rate limit. Wait a few minutes and retry."

    if err:
        return f"Facebook login error code {err!r}. URL: {final_url}"

    # HTML-based checks
    soup = BeautifulSoup(html, "html.parser")
    for attrs in [
        {"id": "error_box"},
        {"class": "_9ay7"},
        {"data-testid": "royal_login_error"},
        {"class": "login_error_box"},
        {"id": "loginform_error"},
        {"role": "alert"},
    ]:
        el = soup.find(attrs=attrs)
        if el:
            msg = el.get_text(strip=True)
            if len(msg) > 3:
                return f"Facebook says: \"{msg}\""

    if any(k in low for k in ["incorrect password", "wrong password", "re-enter your password"]):
        return "Wrong password."
    if "find your account" in low or "doesn't match" in low:
        return "Account not found or email mismatch."
    if "too many" in low or "temporarily blocked" in low:
        return "Too many login attempts — wait 15–30 minutes."
    if "account has been disabled" in low:
        return "Account is disabled."

    # Still on login form?
    if soup.find("input", {"name": "pass"}) or soup.find("form", id="login_form"):
        return (
            "Login rejected — still on login page.\n"
            "  Cause: wrong credentials, form token issue, or IP blocked.\n"
            f"  Final URL: {final_url}\n"
            f"  Debug HTML → {DEBUG_FILE}"
        )

    return f"Unknown failure. Final URL: {final_url}\n  Debug HTML → {DEBUG_FILE}"


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOGIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def login(email: str, password: str) -> requests.Session:
    """
    Full 3-step Facebook login.
    Returns authenticated requests.Session, or raises RuntimeError.
    """
    session = requests.Session()
    session.headers.update(HEADERS)

    _step1_seed_cookies(session)
    action, fields = _step2_get_form(session)
    response = _step3_post_login(session, action, fields, email, password)

    # Primary check: auth cookies present
    if _is_authenticated(session):
        _print_success(session, email)
        _save_session(session, email)
        return session

    # Secondary check: follow intermediate redirects
    # (save-device, privacy consent, dummy registration page, etc.)
    mid_page_keywords = [
        "save-device", "save_device", "reg/dummy",
        "privacy/consent", "two_step", "recover",
    ]
    if any(k in response.url for k in mid_page_keywords):
        _dim(f"         Intermediate page detected, following: {response.url}")
        try:
            r2 = session.get(
                response.url,
                headers={**HEADERS, "Referer": URL_LOGIN},
                timeout=20,
                allow_redirects=True,
            )
            if _is_authenticated(session):
                _print_success(session, email)
                _save_session(session, email)
                return session
        except requests.RequestException:
            pass

    DEBUG_FILE.write_text(response.text, encoding="utf-8")
    raise RuntimeError(_diagnose(response))


# ══════════════════════════════════════════════════════════════════════════════
# SESSION PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

def _print_success(session: requests.Session, email: str) -> None:
    uid = session.cookies.get("c_user", "?")
    print(f"\n{GRN}{BLD}✓ Login successful!{RST}")
    print(f"  User ID : {CYN}{uid}{RST}")
    print(f"  Email   : {email}")


def _save_session(session: requests.Session, email: str) -> None:
    uid = session.cookies.get("c_user", "")
    data = {
        "email":    email,
        "uid":      uid,
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cookies":  {k: v for k, v in session.cookies.items()},
    }
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"  Saved   : {GRN}{SESSION_FILE}{RST}")


def load_session() -> tuple:
    """Load saved session for check_comments.py. Exits if missing."""
    if not SESSION_FILE.exists():
        print(f"{RED}[✗] No session file. Run:  python3 login.py{RST}")
        sys.exit(1)
    try:
        meta = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        print(f"{RED}[✗] Session file corrupt: {e}{RST}")
        sys.exit(1)
    session = requests.Session()
    session.headers.update(HEADERS)
    session.cookies.update(meta.get("cookies", {}))
    return session, meta


def check_session() -> None:
    session, meta = load_session()
    print(f"[*] Session: {meta.get('email','?')}  uid={meta.get('uid','?')}  saved={meta.get('saved_at','?')}")
    if _is_authenticated(session):
        print(f"{GRN}[✓] VALID{RST}")
    else:
        print(f"{RED}[✗] EXPIRED — run: python3 login.py{RST}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _info(msg: str) -> None:
    print(f"{BLD}{msg}{RST}")

def _dim(msg: str) -> None:
    print(f"{DIM}{msg}{RST}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        prog="login.py",
        description="Facebook login (www.facebook.com) — saves cookies to fb_session.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 login.py                        # interactive (safest)\n"
            "  python3 login.py -e you@example.com     # prompts for password\n"
            "  python3 login.py -e EMAIL -p PASS       # fully automated\n"
            "  python3 login.py --check                # verify saved session\n"
        ),
    )
    ap.add_argument("-e", "--email",    metavar="EMAIL",    help="Facebook email or phone")
    ap.add_argument("-p", "--password", metavar="PASSWORD", help="Password (interactive prompt is safer)")
    ap.add_argument("--check", action="store_true",         help="Check if saved session is still valid")
    args = ap.parse_args()

    if args.check:
        check_session()
        return

    print(f"\n{BLD}{MAG}╔══════════════════════════════╗")
    print(f"║   Facebook Login — login.py  ║")
    print(f"╚══════════════════════════════╝{RST}\n")

    email    = args.email    or input("Email / phone : ").strip()
    password = args.password or getpass.getpass("Password      : ")

    if not email:
        print(f"{RED}[✗] Email is required.{RST}"); sys.exit(1)
    if not password:
        print(f"{RED}[✗] Password is required.{RST}"); sys.exit(1)

    print()
    try:
        login(email, password)
    except RuntimeError as e:
        print(f"\n{RED}{BLD}[✗] Login failed:{RST}\n")
        print(f"  {e}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
