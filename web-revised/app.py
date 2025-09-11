# app.py  (web-revised — Jinja 프런트엔드)
import os
import threading
from urllib.parse import quote_plus
import requests
from flask import (
    Flask, request, render_template, redirect,
    Response, abort
)

TEMPLATE_DIR = os.getenv("TEMPLATE_DIR", "templates")
STATIC_DIR   = os.getenv("STATIC_DIR", "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.config.update(
    JSON_AS_ASCII=False,
    JSONIFY_MIMETYPE="application/json; charset=utf-8",
    TEMPLATES_AUTO_RELOAD=True,
)

# ---------- Upstream(API) autodiscovery ----------
# 1) 사이드카가 갱신하는 파일이 우선
API_BASE_FILE = os.getenv("API_BASE_FILE", "/opt/web-shared/api_base")

# 2) 환경변수 폴백
_ENV_API_BASE = (os.getenv("API_BASE") or "").rstrip("/")
if not _ENV_API_BASE:
    _ENV_API_HOST = os.getenv("API_HOST", "127.0.0.1")
    _ENV_API_PORT = os.getenv("API_PORT", "8000")
    _ENV_API_BASE = f"http://{_ENV_API_HOST}:{_ENV_API_PORT}"

# 파일 변경 감지 캐시
_api_base_cache = None        # type: str | None
_api_base_mtime = None        # type: float | None
_api_lock = threading.Lock()

def _read_api_base_file() -> str | None:
    path = API_BASE_FILE
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    except Exception:
        return None

    global _api_base_cache, _api_base_mtime
    with _api_lock:
        # mtime이 바뀌었을 때만 재읽기
        if _api_base_mtime is None or _api_base_mtime != st.st_mtime:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    val = (f.read() or "").strip().rstrip("/")
                # 간단한 유효성 체크
                if val.startswith("http://") or val.startswith("https://"):
                    _api_base_cache = val
                else:
                    # 형식이 이상하면 무시하고 기존 캐시 유지
                    pass
                _api_base_mtime = st.st_mtime
            except Exception:
                # 읽기 실패 시 캐시 유지
                pass
    return _api_base_cache

def get_api_base() -> str:
    # 파일이 유효하면 그것을, 아니면 환경변수 폴백
    fb = _read_api_base_file()
    return fb or _ENV_API_BASE

def api_url(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return get_api_base().rstrip("/") + path

def _forward_headers():
    hop_by_hop = {
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade"
    }
    headers = {}
    for k, v in request.headers.items():
        if k.lower() in hop_by_hop or k.lower() == "host":
            continue
        headers[k] = v
    headers["X-Forwarded-For"]   = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", request.scheme)
    headers["X-Forwarded-Host"]  = request.headers.get("X-Forwarded-Host", request.host)
    return headers

def _copy_set_cookie(upstream_resp, flask_resp):
    cookies = []
    try:
        cookies = upstream_resp.raw.headers.getlist("Set-Cookie")  # type: ignore[attr-defined]
    except Exception:
        sc = upstream_resp.headers.get("Set-Cookie")
        if sc:
            cookies = [sc]
    for c in cookies:
        flask_resp.headers.add("Set-Cookie", c)

def _wants_html() -> bool:
    return "text/html" in (request.headers.get("Accept", "") or "")

def api_call(method: str, path: str):
    """일반 API 프록시 (리다이렉트는 그대로 전달)."""
    url = api_url(path)
    try:
        resp = requests.request(
            method=method.upper(),
            url=url,
            params=request.args,
            data=request.get_data() if request.get_data() else None,
            headers=_forward_headers(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )
        excluded = {
            "transfer-encoding", "connection", "keep-alive",
            "proxy-authenticate", "proxy-authorization", "te",
            "trailers", "upgrade"
        }
        headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in excluded]
        return Response(resp.content, status=resp.status_code, headers=headers)
    except requests.RequestException as e:
        return Response(
            f'{{"ok":false,"error":"upstream error: {str(e)}"}}',
            status=502, mimetype="application/json; charset=utf-8"
        )

# ---------- helper ----------
def fetch_current_user():
    try:
        r = requests.get(api_url("/api/session"), cookies=request.cookies, timeout=5)
        if r.ok:
            return r.json().get("user")
    except Exception:
        pass
    return None

# ---------- Health ----------
@app.get("/healthz")
def healthz():
    return "ok", 200

@app.get("/favicon.ico")
def favicon():
    return "", 204

# ---------- Pages ----------
@app.get("/")
def index_page():
    user = fetch_current_user()
    subs = []
    try:
        r = requests.get(api_url("/api/subjects"), cookies=request.cookies, timeout=8)
        if r.ok:
            subs = r.json().get("subjects", [])
    except Exception:
        subs = []
    return render_template("index.html", subs=subs, current_user=user)

@app.get("/login")
def login_page():
    user = fetch_current_user()
    return render_template("login.html", login_action="/api/login", current_user=user)

@app.get("/register")
def register_page():
    user = fetch_current_user()
    return render_template("register.html", register_action="/api/register", current_user=user)

@app.get("/subject/<name>")
def subject_page(name):
    user = fetch_current_user()
    try:
        r = requests.get(api_url(f"/api/subject/{name}"), cookies=request.cookies, timeout=10)
        if r.status_code == 404:
            abort(404)
        r.raise_for_status()
        data = r.json()
        sub = data.get("subject")
        videos = data.get("videos", [])
        try:
            idx = int(request.args.get("v", "0"))
        except ValueError:
            idx = 0
        idx = max(0, min(idx, len(videos)-1)) if videos else -1
        current = videos[idx] if videos else None
        return render_template("subject.html",
                               sub=sub, videos=videos, current=current, idx=idx,
                               current_user=user)
    except Exception:
        abort(500)

# ---------- Convenience (GET -> UI) ----------
@app.get("/api/login")
def api_login_redirect_to_ui():
    return redirect("/login", code=302)

@app.get("/api/register")
def api_register_redirect_to_ui():
    return redirect("/register", code=302)

# ---------- Special handling: auth POST ----------
def _auth_post_proxy(kind: str):  # kind in {"login","register"}
    url = api_url(f"/api/{kind}")
    try:
        upstream = requests.request(
            method="POST",
            url=url,
            params=request.args,
            data=request.get_data() if request.get_data() else None,
            headers=_forward_headers(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=10,
        )
    except requests.RequestException as e:
        return Response(
            f'{{"ok":false,"error":"upstream error: {str(e)}"}}',
            status=502, mimetype="application/json; charset=utf-8"
        )

    if 300 <= upstream.status_code < 400 and upstream.headers.get("Location"):
        excluded = {"transfer-encoding","connection","keep-alive","proxy-authenticate",
                    "proxy-authorization","te","trailers","upgrade"}
        headers = [(k, v) for k, v in upstream.headers.items() if k.lower() not in excluded]
        return Response(upstream.content, status=upstream.status_code, headers=headers)

    if _wants_html():
        next_url = "/"
        err = None
        msg = None
        try:
            payload = upstream.json()
        except Exception:
            payload = None

        if payload and payload.get("ok"):
            if kind == "login":
                next_url = payload.get("next") or "/"
                resp = redirect(next_url, code=302)
            else:  # register
                msg = payload.get("message") or "가입 완료! 로그인해주세요."
                resp = redirect("/login?msg=" + quote_plus(msg), code=302)
        else:
            if payload:
                err = payload.get("error") or "요청 실패"
            else:
                err = f"요청 실패 (status={upstream.status_code})"
            to = "/login" if kind == "login" else "/register"
            resp = redirect(f"{to}?err=" + quote_plus(err), code=302)

        _copy_set_cookie(upstream, resp)
        return resp

    excluded = {"transfer-encoding","connection","keep-alive","proxy-authenticate",
                "proxy-authorization","te","trailers","upgrade"}
    headers = [(k, v) for k, v in upstream.headers.items() if k.lower() not in excluded]
    return Response(upstream.content, status=upstream.status_code, headers=headers)

@app.post("/api/login")
def api_login_post():
    return _auth_post_proxy("login")

@app.post("/api/register")
def api_register_post():
    return _auth_post_proxy("register")

# ---------- Generic API proxy ----------
@app.route("/api/<path:p>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
def api_proxy(p):
    return api_call(request.method, f"/api/{p}")

# ---------- Run ----------
if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port, debug=True)
