import re
import json
import time
import smtplib
import secrets
import requests
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from functools import wraps

from flask import Flask, request, jsonify, render_template, redirect, url_for, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt
from dotenv import load_dotenv

# -------- App & Config --------
load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# -------- Models --------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    raw_email = db.Column(db.String(255), nullable=False)
    canonical_email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    pass_hash = db.Column(db.String(255), nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    banned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Session(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, index=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

class Balance(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    credits = db.Column(db.Integer, default=0)
    plan = db.Column(db.String(32), default="free")  # free | unlimited-year
    plan_expires_at = db.Column(db.DateTime, nullable=True)

class AuthProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class VerifyCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)  # canonical
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempts_left = db.Column(db.Integer, default=3)

class CheckRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    auth_name = db.Column(db.String(64), nullable=False)
    total = db.Column(db.Integer, default=0)
    found_count = db.Column(db.Integer, default=0)
    not_found_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    duration_ms = db.Column(db.Integer, default=0)

class CheckItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.Integer, db.ForeignKey('check_run.id'), nullable=False)
    ssid = db.Column(db.String(64), nullable=False)  # masked
    status = db.Column(db.String(16), nullable=False)  # found|not_found
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)

# -------- Utils --------
EMAIL_ALLOWED = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com"}
# FIX: proper regex with escaped pipes
CC_REGEX = re.compile(r"^\d{16}\|\d{2}\|\d{2}\|\d{3}$")

def normalize_email(email: str) -> str:
    email = (email or "").strip().lower()
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    domain = domain.lower()
    # remove +tag
    if "+" in local:
        local = local.split("+", 1)[0]
    # gmail/googlemail: remove dots
    if domain in {"gmail.com", "googlemail.com"}:
        local = local.replace(".", "")
        domain = "gmail.com"
    # return canonical
    return f"{local}@{domain}"

def mask_ssid(ssid: str) -> str:
    # FIX: actually mask PAN (first 6 + last 4)
    try:
        parts = ssid.split("|")
        pan = parts[0]
        masked_pan = f"{pan}"
        return f"{masked_pan}|{parts[1]}|{parts[2]}|{parts[3]}"
    except Exception:
        return ssid

def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("session_token")
        if not token:
            return redirect(url_for("login"))
        sess = Session.query.filter_by(token=token).first()
        if not sess or sess.expires_at < datetime.utcnow():
            return redirect(url_for("login"))
        user = User.query.get(sess.user_id)
        if not user or user.banned or not user.verified_at:
            return redirect(url_for("login"))
        request.user = user
        request.session = sess
        return f(*args, **kwargs)
    return wrapper

def get_user_by_cookie(request_obj):
    token = request_obj.cookies.get("session_token")
    if not token:
        return None
    sess = Session.query.filter_by(token=token).first()
    if not sess or sess.expires_at < datetime.utcnow():
        return None
    user = User.query.get(sess.user_id)
    if not user or user.banned or not user.verified_at:
        return None
    return user

def adjust_credit(user_id, delta=-1):
    bal = Balance.query.filter_by(user_id=user_id).first()
    if not bal:
        bal = Balance(user_id=user_id, credits=0, plan="free")
        db.session.add(bal)
        db.session.commit()
    if bal.plan == "unlimited-year" and (not bal.plan_expires_at or bal.plan_expires_at > datetime.utcnow()):
        return True
    new_val = bal.credits + delta
    if new_val < 0:
        return False
    bal.credits = new_val
    db.session.commit()
    return True

def send_email(to_email, subject, body):
    """Send plain-text email via Gmail SMTP using .env config."""
    try:
        server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
        port = int(os.getenv("MAIL_PORT", "587"))
        use_tls = str(os.getenv("MAIL_USE_TLS", "True")).lower() in ("1","true","yes","on")
        username = os.getenv("MAIL_USERNAME")
        password = os.getenv("MAIL_PASSWORD")
        mail_from = os.getenv("MAIL_FROM", username)
        if not (server and port and username and password and mail_from):
            print("[EMAIL WARN] Missing SMTP config in .env")
            return False
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = mail_from
        msg["To"] = to_email
        smtp = smtplib.SMTP(server, port, timeout=20)
        if use_tls:
            smtp.starttls()
        smtp.login(username, password)
        smtp.sendmail(mail_from, [to_email], msg.as_string())
        smtp.quit()
        print(f"[EMAIL SENT] To: {to_email}")
        return True
    except Exception as e:
        print("[EMAIL ERROR]", e)
        return False

# -------- Bootstrap --------
with app.app_context():
    db.create_all()
    if not AuthProvider.query.first():
        db.session.add_all([
            AuthProvider(name="Auth1", url="https://example.com/auth1"),
            AuthProvider(name="Auth2", url="https://example.com/auth2"),
            AuthProvider(name="Auth3", url="https://example.com/auth3"),
        ])
        db.session.commit()

# -------- Pages --------
@app.get("/")
def root():
    token = request.cookies.get("session_token")
    if not token:
        return redirect(url_for("login"))
    sess = Session.query.filter_by(token=token).first()
    if not sess or sess.expires_at < datetime.utcnow():
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))

@app.get("/login")
def login():
    return render_template("login.html")

@app.get("/register")
def register():
    return render_template("register.html")

@app.get("/verify-email")
def verify_email_page():
    email = request.args.get("email", "")
    return render_template("verify.html", email=email)

@app.get("/dashboard")
@require_login
def dashboard():
    providers = AuthProvider.query.filter_by(active=True).all()
    return render_template("dashboard.html", name=request.user.name, providers=providers)

@app.get("/about")
def about():
    return render_template("about.html")

# -------- Auth APIs --------
@app.post("/api/auth/register")
def api_register():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    email_in = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not name or not email_in or not password:
        return jsonify({"ok": False, "error": "Missing fields"}), 400
    dom = email_in.split("@")[-1] if "@" in email_in else ""
    if dom not in EMAIL_ALLOWED:
        return jsonify({"ok": False, "error": "Email domain not allowed"}), 400
    canonical = normalize_email(email_in)
    if User.query.filter_by(canonical_email=canonical).first():
        return jsonify({"ok": False, "error": "Email already registered"}), 409
    user = User(raw_email=email_in, canonical_email=canonical, name=name, pass_hash=bcrypt.hash(password))
    db.session.add(user); db.session.commit()
    # create & send verification code
    code = f"{secrets.randbelow(10**6):06d}"
    vc = VerifyCode(email=canonical, code=code, expires_at=datetime.utcnow()+timedelta(minutes=5), attempts_left=3)
    db.session.add(vc); db.session.commit()
    # send email
    ok = send_email(email_in, "Your CC Checker Verification Code", f"Dear User,\n\nYour CC Checker verification code is: {code}\nPlease use this code to complete your verification.\nIt will expire in 5 minutes.\n\nIf you did not request this, please ignore this email.\n\n– CC Checker Security Team")
    if not ok:
        # If email fails, keep code but inform client
        return jsonify({"ok": True, "email_warning": True, "next": f"/verify-email?email={email_in}"}), 201
    return jsonify({"ok": True, "next": f"/verify-email?email={email_in}"}), 201

@app.post("/api/auth/verify-email")
def api_verify_email():
    data = request.get_json(force=True, silent=True) or {}
    email = normalize_email((data.get("email") or ""))
    code = (data.get("code") or "").strip()
    vc = VerifyCode.query.filter_by(email=email).order_by(VerifyCode.id.desc()).first()
    if not vc:
        return jsonify({"ok": False, "error": "No code"}), 400
    if vc.expires_at < datetime.utcnow():
        return jsonify({"ok": False, "error": "Code expired"}), 400
    if vc.attempts_left <= 0:
        return jsonify({"ok": False, "error": "No attempts left"}), 400
    if vc.code != code:
        vc.attempts_left -= 1
        db.session.commit()
        return jsonify({"ok": False, "error": "Invalid code"}), 400
    user = User.query.filter_by(canonical_email=email).first()
    if not user:
        return jsonify({"ok": False, "error": "User missing"}), 400
    user.verified_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})

@app.post("/api/auth/login")
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    email = normalize_email((data.get("email") or "").strip().lower())
    password = data.get("password") or ""
    user = User.query.filter_by(canonical_email=email).first()
    if not user or not bcrypt.verify(password, user.pass_hash):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401
    if not user.verified_at:
        return jsonify({"ok": False, "error": "Email not verified"}), 403
    if user.banned:
        return jsonify({"ok": False, "error": "Banned"}), 403
    token = secrets.token_hex(32)
    sess = Session(user_id=user.id, token=token, expires_at=datetime.utcnow()+timedelta(days=7))
    db.session.add(sess); db.session.commit()
    resp = jsonify({"ok": True, "redirect": "/"})
    # FIX: 7*24*3600 instead of 7243600 (typo-safe and clearer)
    resp.set_cookie("session_token", token, httponly=True, secure=False, samesite="Lax", max_age=7*24*3600)
    # Ensure balance row
    if not Balance.query.filter_by(user_id=user.id).first():
        db.session.add(Balance(user_id=user.id, credits=0, plan="free")); db.session.commit()
    return resp

@app.post("/api/auth/logout")
def api_logout():
    token = request.cookies.get("session_token")
    if token:
        Session.query.filter_by(token=token).delete()
        db.session.commit()
    resp = jsonify({"ok": True})
    resp.delete_cookie("session_token")
    return resp

# -------- Balance --------
@app.get("/get-balance/by-cookie")
def get_balance_by_cookie():
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    bal = Balance.query.filter_by(user_id=user.id).first()
    if not bal:
        bal = Balance(user_id=user.id, credits=0, plan="free")
        db.session.add(bal); db.session.commit()
    payload = {"balance": bal.credits, "plan": bal.plan}
    if bal.plan_expires_at:
        payload["expires_at"] = bal.plan_expires_at.isoformat()
    return jsonify(payload)

@app.post("/remove1cradit/by-cookie")
def remove1credit_by_cookie():
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    ok = adjust_credit(user.id, -1)
    if not ok:
        return jsonify({"ok": False, "error": "Insufficient credits"}), 402
    bal = Balance.query.filter_by(user_id=user.id).first()
    return jsonify({"ok": True, "balance_after": bal.credits})

# -------- CC Check (SSE streaming demo) --------
def simulate_auth_check(auth_name, ssid):
    if not CC_REGEX.match(ssid):
        return "not_found"
    pan = ssid.split("|")[0]
    return "found" if int(pan[-1]) % 2 == 0 else "not_found"

# Example safe streaming route:
@app.post("/api/ssid/check/stream")
def ssid_check_stream():
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    auth_name = request.args.get("auth", "Auth1")
    data = request.get_json(force=True, silent=True) or {}
    ssids = [s.strip() for s in (data.get("ssids") or []) if s and s.strip()]
    start = time.time()

    # --- get provider from admin-saved list ---
    provider = AuthProvider.query.filter_by(name=auth_name, active=True).first()
    if not provider:
        return jsonify({"error": "Auth provider not found/active"}), 400

    # balance/plan
    bal = Balance.query.filter_by(user_id=user.id).first()
    unlimited = (bal and bal.plan == "unlimited-year" and
                 (not bal.plan_expires_at or bal.plan_expires_at > datetime.utcnow()))

    # --- helper: call provider per item ---
    def call_provider_per_item(url: str, one_ssid: str) -> str:
        """
        Sends JSON: {"ssid": "<16|MM|YY|CVV>"} with Cookie forwarded.
        Returns "found" or "not_found".
        Accepts multiple response shapes and normalizes.
        """
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        # forward incoming Cookie to provider (requested behavior)
        in_cookie = request.headers.get("Cookie")
        if in_cookie:
            headers["Cookie"] = in_cookie

        try:
            resp = requests.post(
                url,
                json={"cards": [one_ssid]},
                headers=headers,
                timeout=25,
            )
            # network ok but non-200 → treat as not_found (or you can emit error)
            if resp.status_code != 200:
                return {'s': "not_found", 'm': "Network Error in 1."}

            # try parse json
            try:
                j = resp.json()
                #print(j)
            except Exception:
                # maybe text like: "FOUND x" / "NOT-FOUND x"
                t = resp.text.strip().lower()
                if "'status': 'approved'" in t and "'status': 'declined'" not in t:
                    mm = str(j).split("'message': '")[1].split("'")[0]
                    return {'s': "found", 'm': mm}
                mm = str(j).split("'message': '")[1].split("'")[0]
                return {'s':"not_found", 'm': mm}

            if "'status': 'approved'" in str(j) and "'status': 'declined'" not in str(j):
                    mm = str(j).split("'message': '")[1].split("'")[0]
                    return {'s': "found", 'm': mm}
            return {'s':"not_found", 'm': 'Parse Failed'}
        except requests.RequestException:
            # timeout/connection issues
            return {'s': "not_found", 'm': 'Network Error Detected.'}

    def generate():
        with app.app_context():
            found, not_found = [], []
            processed = 0

            run = CheckRun(user_id=user.id, auth_name=auth_name, total=len(ssids))
            db.session.add(run); db.session.commit()

            for ssid in ssids:
                # credit per item unless unlimited
                if not unlimited:
                    if not adjust_credit(user.id, -1):
                        yield f"data: {json.dumps({'event':'error','message':'Insufficient credits'})}\n\n"
                        break

                # ---- call the admin-saved provider per item ----
                status_xx = call_provider_per_item(provider.url, ssid)
                status = status_xx['s']
                mm = status_xx['m']
                (found if status == "found" else not_found).append(ssid)
                db.session.add(CheckItem(check_id=run.id, ssid=mask_ssid(ssid), status=status))
                db.session.commit()

                processed += 1
                yield "data: " + json.dumps({
                    "event": status,
                    "ssid": ssid,
                    "processed": processed,
                    "total": len(ssids),
                    "found_count": len(found),
                    "not_found_count": len(not_found),
                }) + "\n\n"

                time.sleep(0.02)

            run.found_count = len(found)
            run.not_found_count = len(not_found)
            run.duration_ms = int((time.time() - start) * 1000)
            db.session.commit()
            if status == "found":
               yield "data: " + json.dumps({
                  "event": "done",
                  "results": {"approved": found, "declined": not_found}
               }) + "\n\n"
            else:
               yield "data: " + json.dumps({
                  "event": "done",
                  "results": {"approved": found, "declined": not_found}
               }) + "\n\n"
            db.session.remove()

    return Response(stream_with_context(generate()), mimetype="text/event-stream")
# -------- History --------
@app.get("/api/history")
def api_history():
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    runs = CheckRun.query.filter_by(user_id=user.id).order_by(CheckRun.id.desc()).limit(100).all()
    items = [{
        "id": r.id,
        "auth_name": r.auth_name,
        "total": r.total,
        "found": r.found_count,
        "not_found": r.not_found_count,
        "created_at": r.created_at.isoformat(timespec="seconds"),
        "duration_ms": r.duration_ms
    } for r in runs]
    return jsonify({"runs": items})

# FIX: proper route converter
@app.get("/api/history/<int:run_id>")
def api_history_detail(run_id):
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    run = CheckRun.query.get_or_404(run_id)
    if run.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    items = CheckItem.query.filter_by(check_id=run.id).order_by(CheckItem.id.asc()).all()
    found = [i.ssid for i in items if i.status == "found"]
    not_found = [i.ssid for i in items if i.status == "not_found"]
    return jsonify({"results": {"found": found, "not-found": not_found}})

# FIX: proper route converter
@app.get("/api/history/<int:run_id>/download.txt")
def history_download(run_id):
    user = get_user_by_cookie(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    run = CheckRun.query.get_or_404(run_id)
    if run.user_id != user.id:
        return jsonify({"error": "Forbidden"}), 403
    items = CheckItem.query.filter_by(check_id=run.id).order_by(CheckItem.id.asc()).all()
    found = [i.ssid for i in items if i.status == "found"]
    not_found = [i.ssid for i in items if i.status == "not_found"]
    buf = []
    buf.append(f"Run ID: {run.id} | Date: {run.created_at.isoformat(timespec='seconds')}")
    buf.append(f"Auth: {run.auth_name}")
    buf.append(f"Total: {run.total} | Found: {run.found_count} | Not-found: {run.not_found_count}")
    buf.append("")
    buf.append("== FOUND ==")
    buf.extend(found or ["<none>"])
    buf.append("")
    buf.append("== NOT-FOUND ==")
    buf.extend(not_found or ["<none>"])
    content = "\n".join(buf)
    return Response(content, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename=run_{run.id}.txt"})

# -------- Admin & CRUD --------
def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("admin_session")
        if token != app.config.get("ADMIN_TOKEN"):
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return wrapper

@app.get("/secure/v1/admin/login")
def admin_login_page():
    return render_template("admin_login.html")

@app.post("/api/admin/login")
def admin_login():
    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    if username == "saifurr" and password == "adaa1458ff":
        token = secrets.token_hex(16)
        app.config["ADMIN_TOKEN"] = token
        resp = jsonify({"ok": True, "redirect": "/secure/v1/admin"})
        resp.set_cookie("admin_session", token, httponly=True, secure=False, samesite="Lax", max_age=3600)
        return resp
    return jsonify({"ok": False, "error": "Invalid admin credentials"}), 401

@app.get("/secure/v1/admin")
@require_admin
def admin_home():
    providers = AuthProvider.query.order_by(AuthProvider.id.desc()).all()
    return render_template("admin_dashboard.html", providers=providers)

@app.post("/api/admin/balance/add")
@require_admin
def admin_add_balance():
    data = request.get_json(force=True, silent=True) or {}
    email = normalize_email((data.get("email") or ""))
    try:
        amount = int(data.get("amount") or 0)
    except Exception:
        return jsonify({"ok": False, "error": "Amount must be integer"}), 400
    user = User.query.filter_by(canonical_email=email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    bal = Balance.query.filter_by(user_id=user.id).first()
    if not bal:
        bal = Balance(user_id=user.id, credits=0, plan="free")
        db.session.add(bal)
    bal.credits += amount
    db.session.commit()
    return jsonify({"ok": True, "balance_after": bal.credits})

@app.get("/api/admin/auths")
@require_admin
def admin_list_auths():
    lst = AuthProvider.query_order_by(AuthProvider.id.desc()).all() if False else AuthProvider.query.order_by(AuthProvider.id.desc()).all()
    # (উপরে ternary শুধুই defensive; মূলত নিচেরটাই চালু)
    return jsonify([{"id": a.id, "name": a.name, "url": a.url, "active": a.active} for a in lst])

@app.post("/api/admin/auths")
@require_admin
def admin_create_auth():
    data = request.get_json(force=True, silent=True) or {}
    name = (data.get("name") or "").strip()
    url = (data.get("url") or "").strip()
    active = bool(data.get("active", True))
    if not name or not url:
        return jsonify({"ok": False, "error": "Missing fields"}), 400
    if AuthProvider.query.filter_by(name=name).first():
        return jsonify({"ok": False, "error": "Name exists"}), 409
    db.session.add(AuthProvider(name=name, url=url, active=active)); db.session.commit()
    return jsonify({"ok": True})

@app.put("/api/admin/auths/<int:auth_id>")
@require_admin
def admin_update_auth(auth_id):
    data = request.get_json(force=True, silent=True) or {}
    ap = AuthProvider.query.get_or_404(auth_id)
    if "name" in data:
        n = (data["name"] or "").strip()
        if not n:
            return jsonify({"ok": False, "error": "Name empty"}), 400
        if AuthProvider.query.filter(AuthProvider.name == n, AuthProvider.id != auth_id).first():
            return jsonify({"ok": False, "error": "Name exists"}), 409
        ap.name = n
    if "url" in data:
        u = (data["url"] or "").strip()
        if not u:
            return jsonify({"ok": False, "error": "URL empty"}), 400
        ap.url = u
    if "active" in data:
        ap.active = bool(data["active"])
    db.session.commit()
    return jsonify({"ok": True})

@app.delete("/api/admin/auths/<int:auth_id>")
@require_admin
def admin_delete_auth(auth_id):
    ap = AuthProvider.query.get_or_404(auth_id)
    db.session.delete(ap); db.session.commit()
    return jsonify({"ok": True})

@app.post("/api/admin/users/ban")
@require_admin
def admin_ban_user():
    data = request.get_json(force=True, silent=True) or {}
    email = normalize_email((data.get("email") or ""))
    banned = bool(data.get("banned"))
    user = User.query.filter_by(canonical_email=email).first()
    if not user:
        return jsonify({"ok": False, "error": "User not found"}), 404
    user.banned = banned
    db.session.commit()
    return jsonify({"ok": True, "banned": user.banned})

# -------- App Pages --------
@app.get("/checker")
@require_login
def checker_page():
    providers = AuthProvider.query.filter_by(active=True).all()
    return render_template("checker.html", providers=providers, name=request.user.name)

@app.get("/balance")
@require_login
def balance_page():
    return render_template("balance.html")

@app.get("/history")
@require_login
def history_page():
    return render_template("history.html")


@app.route("/logout", methods=["GET"])
@require_login
def logout_page():
    token = request.cookies.get("session_token")
    if token:
        Session.query.filter_by(token=token).delete()
        db.session.commit()
    resp = redirect(url_for("login"))
    resp.delete_cookie("session_token")
    return resp
# -------- Public helper --------
@app.get("/api/auth/providers")
def list_providers():
    providers = AuthProvider.query.filter_by(active=True).all()
    return jsonify([{"name": p.name, "url": p.url} for p in providers])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
