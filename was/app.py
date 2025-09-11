# app.py — WAS(API) for OpenSolutions (HTML redirect + JSON 동시지원)
import os, re
from urllib.parse import urlparse, unquote, quote_plus
from flask import Flask, request, jsonify, session, redirect, abort
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text

# --- Redis/Session ---
try:
    import redis  # redis-py >=5
    from flask_session import Session
except Exception:
    redis = None
    Session = None

# ---------- DB URL builder ----------
def build_db_url_from_parts() -> str | None:
    host = os.getenv("DB_HOST")
    user = os.getenv("DB_USER")
    password = os.getenv("DB_PASS")
    name = os.getenv("DB_NAME")
    if not all([host, user, password, name]):
        return None
    port    = os.getenv("DB_PORT", "3306")
    driver  = os.getenv("DB_DRIVER", "pymysql")
    charset = os.getenv("DB_CHARSET", "utf8mb4")
    sslmode = os.getenv("DB_SSL_MODE")
    u = quote_plus(user); p = quote_plus(password)
    qs = f"charset={charset}"
    if sslmode: qs += f"&ssl_mode={quote_plus(sslmode)}"
    return f"mysql+{driver}://{u}:{p}@{host}:{port}/{name}?{qs}"

# ---------- Flask ----------
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me")
app.config.update(JSON_AS_ASCII=False)

# ---------- SQLAlchemy ----------
DB_URL = os.getenv("DB_URL") or build_db_url_from_parts() or "sqlite:////opt/solutions/opensolutions.db"
engine = create_engine(DB_URL, pool_pre_ping=True, future=True)

# ---------- Redis ----------
def _make_redis():
    if redis is None:
        return None
    host = os.getenv("REDIS_HOST")
    if not host:
        return None
    port = int(os.getenv("REDIS_PORT", "6379"))
    password = os.getenv("REDIS_PASS")
    # 타임아웃 짧게: readiness가 빨리 판단되도록
    return redis.Redis(
        host=host,
        port=port,
        password=password,
        socket_connect_timeout=0.5,
        socket_timeout=0.5,
        health_check_interval=30,
    )

_r = _make_redis()

# (선택) 서버사이드 세션을 Redis에 저장
if _r is not None and Session is not None:
    app.config["SESSION_TYPE"] = "redis"
    app.config["SESSION_REDIS"] = _r
    app.config["SESSION_PERMANENT"] = False
    Session(app)

# ---------- Utils ----------
def wants_html() -> bool:
    acc = (request.headers.get("Accept") or "").lower()
    # 브라우저 폼 기본값: text/html,*/*
    return "text/html" in acc and "application/json" not in acc

def require_json_form(keys):
    is_json = request.is_json
    data = {}
    for k in keys:
        data[k] = (request.json.get(k) if is_json else request.form.get(k)) if (request.json if is_json else request.form) else None
    return data

def _truthy(v) -> bool:
    return str(v).lower() in ("1","true","yes","on")

# ---------- Users ----------
def get_user_by_username(username: str):
    sql = text("SELECT username, email, password_hash FROM users WHERE username=:u LIMIT 1")
    with engine.begin() as c:
        return c.execute(sql, {"u": username}).mappings().first()

def username_exists(username: str) -> bool:
    sql = text("SELECT 1 FROM users WHERE username=:u LIMIT 1")
    with engine.begin() as c:
        return c.execute(sql, {"u": username}).first() is not None

def email_exists(email: str) -> bool:
    sql = text("SELECT 1 FROM users WHERE email=:e LIMIT 1")
    with engine.begin() as c:
        return c.execute(sql, {"e": email}).first() is not None

def create_user(username: str, email: str, raw_pw: str):
    try:
        pw_hash = generate_password_hash(raw_pw, method="scrypt")
    except Exception:
        pw_hash = generate_password_hash(raw_pw, method="pbkdf2:sha256")
    sql = text("INSERT INTO users (username, email, password_hash) VALUES (:u, :e, :ph)")
    with engine.begin() as c:
        c.execute(sql, {"u": username, "e": email, "ph": pw_hash})

# ---------- Subjects / Videos ----------
def list_subjects():
    sql = text("SELECT name, image_link FROM subject ORDER BY name")
    with engine.begin() as c:
        return [dict(r) for r in c.execute(sql).mappings().all()]

def get_subject(name: str):
    sql = text("SELECT name, image_link FROM subject WHERE name=:n LIMIT 1")
    with engine.begin() as c:
        row = c.execute(sql, {"n": name}).mappings().first()
        return dict(row) if row else None

VIDEO_TABLE       = os.getenv("VIDEO_TABLE", "video")
VIDEO_SUBJECT_COL = os.getenv("VIDEO_SUBJECT_COL", "name")
VIDEO_URL_COL     = os.getenv("VIDEO_URL_COL", "video_link")
VIDEO_TITLE_COL   = os.getenv("VIDEO_TITLE_COL", "")

_YT_PATTERNS = [
    r"(?:https?://)?(?:www\.)?youtube\.com/watch\?v=([A-Za-z0-9_\-]{6,})",
    r"(?:https?://)?youtu\.be/([A-Za-z0-9_\-]{6,})",
    r"(?:https?://)?(?:www\.)?youtube\.com/shorts/([A-Za-z0-9_\-]{6,})",
]
def _youtube_id(url: str):
    if not url: return None
    for pat in _YT_PATTERNS:
        m = re.search(pat, url)
        if m: return m.group(1)
    return None

def _title_from_url(url: str) -> str:
    try:
        fname = unquote(urlparse(url).path.rsplit("/", 1)[-1]) or ""
        return fname or "영상"
    except Exception:
        return "영상"

def list_videos_for_subject(subj: str):
    sql = text(f"""
        SELECT id,
               {VIDEO_URL_COL} AS link
               {', ' + VIDEO_TITLE_COL + ' AS title' if VIDEO_TITLE_COL else ''}
        FROM {VIDEO_TABLE}
        WHERE {VIDEO_SUBJECT_COL}=:n
          AND {VIDEO_URL_COL} IS NOT NULL
          AND TRIM({VIDEO_URL_COL}) <> ''
        ORDER BY id ASC
    """)
    with engine.begin() as c:
        rows = [dict(r) for r in c.execute(sql, {"n": subj}).mappings().all()]
    out = []
    for i, r in enumerate(rows):
        link = r.get("link")
        yid  = _youtube_id(link or "")
        embed = f"https://www.youtube.com/embed/{yid}" if yid else None
        title = r.get("title") or _title_from_url(link) or f"영상 {i+1}"
        out.append({"id": r.get("id"), "title": title, "link": link, "embed_url": embed})
    return out

# ---------- API: session ----------
@app.get("/api/session")
def api_session():
    return jsonify({"ok": True, "user": session.get("user")})

# ---------- API: auth ----------
@app.post("/api/login")
def api_login():
    d = require_json_form(["username", "password"])
    username = (d.get("username") or "").strip()
    pw       = d.get("password") or ""
    if not username or not pw:
        if wants_html():
            return redirect("/login?err=" + "모든 필드를 입력해주세요.", code=303)
        return jsonify({"ok": False, "error": "모든 필드를 입력해주세요."}), 400

    row = get_user_by_username(username)
    if not row or not check_password_hash(row["password_hash"], pw):
        if wants_html():
            return redirect("/login?err=" + "아이디 또는 비밀번호가 올바르지 않습니다.", code=303)
        return jsonify({"ok": False, "error": "아이디 또는 비밀번호가 올바르지 않습니다."}), 401

    session["user"] = {"username": row["username"], "email": row["email"]}
    next_url = request.args.get("next") or "/"
    if wants_html():
        return redirect(next_url, code=303)
    return jsonify({"ok": True, "next": next_url})

@app.post("/api/register")
def api_register():
    d = require_json_form(["username", "email", "password", "password2"])
    username = (d.get("username") or "").strip()
    email    = (d.get("email") or "").strip().lower()
    pw       = d.get("password") or ""
    pw2      = d.get("password2") or ""

    def _html_or_json_error(msg, status):
        if wants_html():
            return redirect("/register?err=" + msg, code=303)
        return jsonify({"ok": False, "error": msg}), status

    if not username or not email or not pw:
        return _html_or_json_error("모든 필드를 입력해주세요.", 400)
    if pw != pw2:
        return _html_or_json_error("비밀번호 확인이 일치하지 않습니다.", 400)
    if username_exists(username):
        return _html_or_json_error("이미 사용 중인 아이디(username)입니다.", 409)
    if email_exists(email):
        return _html_or_json_error("이미 사용 중인 이메일입니다.", 409)

    try:
        create_user(username, email, pw)
    except Exception as e:
        return _html_or_json_error(f"가입 실패: {e}", 500)

    if wants_html():
        return redirect("/login?msg=" + "가입 완료! 로그인해주세요.", code=303)
    return jsonify({"ok": True, "message": "가입 완료"})

@app.post("/api/logout")
def api_logout():
    session.pop("user", None)
    if wants_html():
        return redirect("/", code=303)
    return jsonify({"ok": True})

# ---------- Catalog ----------
@app.get("/api/subjects")
def api_subjects():
    try:
        return jsonify({"ok": True, "subjects": list_subjects()})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{e}"}), 500

@app.get("/api/subject/<name>")
def api_subject_detail(name):
    sub = get_subject(name)
    if not sub:
        return jsonify({"ok": False, "error": "not found"}), 404
    try:
        vids = list_videos_for_subject(name)
        return jsonify({"ok": True, "subject": sub, "videos": vids})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{e}"}), 500

# ---------- Health (liveness/startup) ----------
@app.get("/health")
def health():
    if _truthy(os.getenv("HEALTH_DB_CHECK", "0")):
        try:
            with engine.begin() as c:
                c.execute(text("SELECT 1"))
            return jsonify({"ok": True, "db": "ok"}), 200
        except Exception as e:
            return jsonify({"ok": False, "db": f"error: {e}"}), 500
    return jsonify({"ok": True, "db": "skipped"}), 200

# ---------- Readiness (Redis 포함) ----------
@app.get("/readyz")
def readyz():
    # Redis 모듈/설정이 없으면 기본은 503 (필요시 완화 플래그로 200 허용)
    allow_no_redis = _truthy(os.getenv("READINESS_ALLOW_NO_REDIS", "0"))

    # DB 간단 체크를 readiness에 포함하고 싶다면 READY_DB_CHECK=1
    check_db = _truthy(os.getenv("READY_DB_CHECK", "0"))
    db_ok = True
    if check_db:
        try:
            with engine.begin() as c:
                c.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False

    if redis is None:
        ok = allow_no_redis and db_ok
        return jsonify({"ok": ok, "redis": "module-not-installed", "db": "ok" if db_ok else "error"}), (200 if ok else 503)
    if _r is None:
        ok = allow_no_redis and db_ok
        return jsonify({"ok": ok, "redis": "not-configured", "db": "ok" if db_ok else "error"}), (200 if ok else 503)

    try:
        _r.ping()
        redis_ok = True
    except Exception as e:
        redis_ok = False

    ok = redis_ok and db_ok
    return jsonify({
        "ok": ok,
        "redis": "ok" if redis_ok else "error",
        "db": "ok" if db_ok else "error" if check_db else "skipped"
    }), (200 if ok else 503)

# ---------- Run (dev) ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8000")), debug=True)
