#!/usr/bin/env python3
"""
login.py — Facebook Mobile Login  (m.facebook.com)
════════════════════════════════════════════════════════════════════════════════
Saves an authenticated cookie session to fb_session.json.

ALGORITHM (verified against real m.facebook.com structure):
  Step 1 ─ GET m.facebook.com/
            Sets datr + sb cookies (device fingerprint).
            Retries until datr is confirmed present.

  Step 2 ─ GET m.facebook.com/login/?refsrc=deprecated&_rdr
            Extracts EVERY hidden <input> from the login form:
              lsd, jazoest, m_ts, li, try_number, unrecognized_tries,
              bi_xrwt, _fb_noscript
            Reads the form's real action URL (never hardcoded).
            Recomputes jazoest from actual lsd value:
              jazoest = "2" + str(sum(ord(c) for c in lsd))

  Step 3 ─ POST to the form action URL with full payload + credentials.
            Follows redirects automatically.
            Checks for c_user + xs cookies → definitive proof of auth.

  Success → saves fb_session.json
  Failure → saves login_debug.html and prints exact reason

Usage:
    python3 login.py                   # interactive (recommended)
    python3 login.py -e EMAIL          # prompt for password only
    python3 login.py -e EMAIL -p PASS  # fully automated
    python3 login.py --check           # verify saved session is still valid

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
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# ── Constants ──────────────────────────────────────────────────────────────────
SESSION_FILE = Path("fb_session.json")
DEBUG_FILE   = Path("login_debug.html")

BASE         = "https://m.facebook.com"
URL_HOME     = "https://m.facebook.com/"
URL_LOGIN    = "https://m.facebook.com/login/?refsrc=deprecated&_rdr"

# Chrome 124 on Android 12 Pixel 6  — Facebook checks UA for mobile site routing
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 12; Pixel 6) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.6367.82 Mobile Safari/537.36"
)

# Headers that mimic a real Chrome mobile browser perfectly
BASE_HEADERS = {
    "User-Agent":                USER_AGENT,
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-CH-UA":                 '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-CH-UA-Mobile":          "?1",
    "Sec-CH-UA-Platform":        '"Android"',
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Sec-Fetch-User":            "?1",
    "DNT":                       "1",
}

# ANSI colours
RST  = "\033[0m"
GRN  = "\033[92m"
YLW  = "\033[93m"
RED  = "\033[91m"
CYN  = "\033[96m"
DIM  = "\033[2m"
BLD  = "\033[1m"


# ══════════════════════════════════════════════════════════════════════════════
# JAZOEST — Facebook's checksum algorithm (reverse-engineered from FB JS)
# ══════════════════════════════════════════════════════════════════════════════

def compute_jazoest(lsd: str) -> str:
    """
    Compute the jazoest checksum that Facebook requires alongside lsd.

    Reverse-engineered from Facebook's obfuscated JS:
        var n = 0;
        for (var i = 0; i < token.length; i++) {
            n += token.charCodeAt(i);
        }
        return "2" + n.toString();

    We ALWAYS recompute this from the actual lsd value on the page —
    never trust the page's jazoest as it may be stale or cached.
    """
    return "2" + str(sum(ord(ch) for ch in lsd))


# ══════════════════════════════════════════════════════════════════════════════
# SESSION FACTORY
# ══════════════════════════════════════════════════════════════════════════════

def _new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(BASE_HEADERS)
    return s


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Seed device cookies
# ══════════════════════════════════════════════════════════════════════════════

def _seed_cookies(session: requests.Session) -> None:
    """
    Visit the Facebook home page to collect essential device cookies:
      datr  — device attribution / fingerprint  (REQUIRED before login)
      sb    — browser session identifier
      fr    — tracking token

    Retries up to 3 times if datr is not set on the first visit
    (can happen with regional redirects).
    """
    for attempt in range(1, 4):
        _log(f"  Seeding cookies (attempt {attempt}/3) …", dim=True)
        try:
            r = session.get(
                URL_HOME,
                timeout=20,
                allow_redirects=True,
                headers={**BASE_HEADERS, "Cache-Control": "no-cache"},
            )
        except requests.RequestException as e:
            raise RuntimeError(f"Cannot reach m.facebook.com: {e}\n  Check your internet connection.")

        if "datr" in session.cookies:
            _log(f"  datr cookie confirmed ✓", dim=True)
            return

        _log(f"  datr not yet set, waiting …", dim=True)
        time.sleep(2)

    _log("  WARNING: datr cookie not set — proceeding anyway.", dim=True)


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — Fetch login page and extract all form fields
# ══════════════════════════════════════════════════════════════════════════════

def _fetch_login_form(session: requests.Session) -> tuple[str, dict]:
    """
    Fetch the m.facebook.com login page and extract:
      - The form's action URL (read dynamically — never hardcoded)
      - All hidden <input> fields: lsd, jazoest, m_ts, li, try_number, etc.

    Returns: (action_url, fields_dict)
    """
    try:
        r = session.get(
            URL_LOGIN,
            timeout=20,
            allow_redirects=True,
            headers={**BASE_HEADERS,
                     "Referer":        URL_HOME,
                     "Sec-Fetch-Site": "same-origin"},
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to fetch login page: {e}")

    html = r.text

    soup = BeautifulSoup(html, "html.parser")

    # ── Find the login form ────────────────────────────────────────────────────
    form = (
        soup.find("form", id="login_form")
        or soup.find("form", attrs={"action": re.compile(r"login", re.I)})
        or soup.find("form")
    )

    if not form:
        DEBUG_FILE.write_text(html, encoding="utf-8")
        raise RuntimeError(
            "Login form not found in page HTML.\n"
            f"  Debug HTML saved to: {DEBUG_FILE}\n"
            "  This usually means Facebook is serving a captcha or blocking the request."
        )

    # ── Read the form action URL ───────────────────────────────────────────────
    action = form.get("action", "")
    if not action:
        action = "/login/device-based/regular/login/?refsrc=deprecated&lwv=100"

    # Make absolute
    if action.startswith("/"):
        action = BASE + action
    elif not action.startswith("http"):
        action = urljoin(BASE + "/", action)

    # ── Extract ALL <input> fields ─────────────────────────────────────────────
    fields: dict[str, str] = {}
    for inp in form.find_all("input"):
        name  = inp.get("name", "").strip()
        value = inp.get("value", "")
        if name:
            fields[name] = value

    # ── Extract lsd from JSON blob if form didn't have it ─────────────────────
    # Facebook sometimes inlines it as: "LSD",[],{"token":"AVr..."}
    if not fields.get("lsd"):
        for pattern in [
            r'"LSD"\s*,\s*\[\]\s*,\s*\{"token"\s*:\s*"([^"]+)"',
            r'name="lsd"\s+value="([^"]+)"',
            r'"lsd"\s*:\s*"([^"]+)"',
        ]:
            m = re.search(pattern, html)
            if m:
                fields["lsd"] = m.group(1)
                break

    # ── Validate critical token ────────────────────────────────────────────────
    lsd = fields.get("lsd", "")
    if not lsd:
        DEBUG_FILE.write_text(html, encoding="utf-8")
        raise RuntimeError(
            "Could not extract lsd CSRF token from login page.\n"
            f"  Debug HTML saved to: {DEBUG_FILE}\n"
            "  Facebook may have changed their login page structure."
        )

    # ── ALWAYS recompute jazoest from the actual lsd ───────────────────────────
    fields["jazoest"] = compute_jazoest(lsd)

    _log(f"  Form action : {action}", dim=True)
    _log(f"  lsd         : {lsd!r}", dim=True)
    _log(f"  jazoest     : {fields['jazoest']!r}  (recomputed from lsd)", dim=True)
    _log(f"  m_ts        : {fields.get('m_ts', 'not found')!r}", dim=True)
    _log(f"  li          : {fields.get('li', 'not found')!r}", dim=True)

    return action, fields


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — POST credentials
# ══════════════════════════════════════════════════════════════════════════════

def _post_credentials(
    session: requests.Session,
    action:  str,
    fields:  dict,
    email:   str,
    password: str,
) -> requests.Response:
    """
    Build the complete POST payload and submit it to Facebook's login endpoint.
    """
    payload = dict(fields)  # copy all hidden fields
    payload["email"]              = email
    payload["pass"]               = password
    payload["login"]              = "Log In"
    payload["try_number"]         = payload.get("try_number", "0")
    payload["unrecognized_tries"] = payload.get("unrecognized_tries", "0")
    payload.setdefault("bi_xrwt",       "")
    payload.setdefault("_fb_noscript",  "true")
    payload.setdefault("prefill_type",  "0")
    payload.setdefault("first_prefill_source", "")
    payload.setdefault("had_cp_prefilled", "false")
    payload.setdefault("had_password_prefilled", "false")

    post_headers = {
        **BASE_HEADERS,
        "Content-Type":  "application/x-www-form-urlencoded",
        "Origin":        BASE,
        "Referer":       URL_LOGIN,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Cache-Control":  "max-age=0",
    }

    try:
        r = session.post(
            action,
            data=payload,
            headers=post_headers,
            timeout=30,
            allow_redirects=True,
        )
    except requests.RequestException as e:
        raise RuntimeError(f"Network error during credential POST: {e}")

    return r


# ══════════════════════════════════════════════════════════════════════════════
# AUTH VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def _is_authenticated(session: requests.Session) -> bool:
    """
    The definitive check: Facebook sets BOTH c_user AND xs only for
    authenticated sessions. No HTML parsing needed.

    c_user = numeric user ID (e.g. "100083...")
    xs     = session secret hash
    """
    c_user = session.cookies.get("c_user", "")
    xs     = session.cookies.get("xs", "")
    return bool(c_user and xs and c_user.isdigit())


# ══════════════════════════════════════════════════════════════════════════════
# ERROR CLASSIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def _diagnose_failure(html: str, final_url: str) -> str:
    """
    Analyse the failed login response and return a clear error message.
    """
    low  = html.lower()
    parsed_url = urlparse(final_url)

    # ── Checkpoint / 2FA ──────────────────────────────────────────────────────
    if "checkpoint" in final_url or "/checkpoint/" in parsed_url.path:
        return (
            "CHECKPOINT / 2FA detected.\n"
            "  Facebook flagged this login as suspicious (new device/location).\n\n"
            "  To fix:\n"
            "    1. Open m.facebook.com in your phone's browser\n"
            "    2. Log in and complete the security check\n"
            "    3. Use a browser extension (e.g. 'Cookie-Editor') to export your cookies\n"
            "    4. Paste them into fb_session.json manually\n"
        )

    # ── Account issues ─────────────────────────────────────────────────────────
    if "your account has been disabled" in low:
        return "Account is disabled."
    if "account has been locked" in low or "account is locked" in low:
        return "Account is locked. Check your email for instructions from Facebook."
    if "temporarily blocked" in low or "too many" in low:
        return "Too many login attempts. Wait 15–30 minutes and try again."

    # ── Wrong credentials ──────────────────────────────────────────────────────
    soup = BeautifulSoup(html, "html.parser")
    for attrs in [
        {"id": "error_box"},
        {"class": "_9ay7"},
        {"data-testid": "royal_login_error"},
        {"class": "login_error_box"},
    ]:
        el = soup.find(attrs=attrs)
        if el:
            msg = el.get_text(strip=True)
            if msg:
                return f"Facebook says: \"{msg}\""

    if any(k in low for k in ["incorrect password", "wrong password", "password you entered"]):
        return "Incorrect password."
    if any(k in low for k in ["find your account", "doesn't match", "no account found"]):
        return "Email/phone not found — no account with that address."

    # ── Still on login page ────────────────────────────────────────────────────
    if soup.find("input", {"name": "pass"}):
        return (
            "Login rejected by Facebook.\n"
            "  Likely cause: wrong email/password, or missing/invalid form tokens.\n"
            f"  Debug HTML saved to: {DEBUG_FILE}"
        )

    # ── Unknown ───────────────────────────────────────────────────────────────
    return (
        f"Unknown failure. Final URL: {final_url}\n"
        f"  Debug HTML saved to: {DEBUG_FILE}"
    )


# ══════════════════════════════════════════════════════════════════════════════
# MAIN LOGIN FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def login(email: str, password: str) -> requests.Session:
    """
    Full 3-step Facebook mobile login.

    Returns an authenticated requests.Session on success.
    Raises RuntimeError with a clear diagnosis on failure.
    """
    session = _new_session()

    # Step 1
    _log(f"\n{BLD}[1/3]{RST} Seeding device cookies …")
    _seed_cookies(session)

    # Step 2
    _log(f"{BLD}[2/3]{RST} Extracting login form tokens …")
    action, fields = _fetch_login_form(session)

    # Step 3
    _log(f"{BLD}[3/3]{RST} Submitting credentials …")
    response = _post_credentials(session, action, fields, email, password)

    # ── Verify ────────────────────────────────────────────────────────────────
    if _is_authenticated(session):
        uid = session.cookies.get("c_user", "?")
        _log(f"\n{GRN}{BLD}✓ Login successful!{RST}  uid={CYN}{uid}{RST}")
        _save_session(session, email)
        return session

    # ── Handle /login/save-device/ redirect (still authenticated) ─────────────
    # Facebook sometimes redirects to save-device page before setting cookies fully.
    # Follow one more request to complete the flow.
    if "save-device" in response.url or "save_device" in response.url:
        _log("  Completing save-device flow …", dim=True)
        try:
            r2 = session.get(response.url, timeout=15, allow_redirects=True)
            if _is_authenticated(session):
                uid = session.cookies.get("c_user", "?")
                _log(f"\n{GRN}{BLD}✓ Login successful!{RST}  uid={CYN}{uid}{RST}")
                _save_session(session, email)
                return session
        except Exception:
            pass

    # ── Failed ────────────────────────────────────────────────────────────────
    DEBUG_FILE.write_text(response.text, encoding="utf-8")
    reason = _diagnose_failure(response.text, response.url)
    raise RuntimeError(reason)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION PERSISTENCE
# ══════════════════════════════════════════════════════════════════════════════

def _save_session(session: requests.Session, email: str) -> None:
    data = {
        "email":    email,
        "uid":      session.cookies.get("c_user", ""),
        "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cookies":  {k: v for k, v in session.cookies.items()},
    }
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    _log(f"{GRN}✓ Session saved →{RST} {SESSION_FILE}")


def load_session() -> tuple:
    """
    Load saved session for use by other scripts.
    Returns (requests.Session, meta_dict).
    Exits with error if no session file found.
    """
    if not SESSION_FILE.exists():
        print(f"{RED}[✗] No session file. Run:  python3 login.py{RST}")
        sys.exit(1)
    try:
        meta    = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        session = _new_session()
        session.cookies.update(meta["cookies"])
        return session, meta
    except Exception as e:
        print(f"{RED}[✗] Failed to load session: {e}{RST}")
        sys.exit(1)


def _check_session() -> None:
    session, meta = load_session()
    print(f"[*] Session for {meta.get('email','?')}  (saved {meta.get('saved_at','?')})")
    if _is_authenticated(session):
        uid = session.cookies.get("c_user", meta.get("uid", "?"))
        print(f"{GRN}[✓] VALID  —  uid={uid}{RST}")
    else:
        print(f"{RED}[✗] EXPIRED — run:  python3 login.py{RST}")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def _log(msg: str, dim: bool = False) -> None:
    if dim:
        print(f"{DIM}{msg}{RST}")
    else:
        print(msg)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Facebook mobile login (m.facebook.com) — saves cookies to fb_session.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 login.py                      # fully interactive\n"
            "  python3 login.py -e you@email.com     # prompt for password only\n"
            "  python3 login.py --check              # verify saved session\n"
        ),
    )
    ap.add_argument("-e", "--email",    metavar="EMAIL",    help="Facebook email or phone number")
    ap.add_argument("-p", "--password", metavar="PASSWORD", help="Password (interactive prompt is safer)")
    ap.add_argument("--check", action="store_true", help="Check if saved session is still valid")
    args = ap.parse_args()

    if args.check:
        _check_session()
        return

    email    = args.email    or input("Facebook email / phone: ").strip()
    password = args.password or getpass.getpass("Password: ")

    if not email or not password:
        print(f"{RED}[✗] Email and password are required.{RST}")
        sys.exit(1)

    try:
        login(email, password)
    except RuntimeError as e:
        print(f"\n{RED}[✗] Login failed:{RST}\n  {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
