import logging
import os
import sqlite3
import secrets
import time
import uuid
from collections import defaultdict
from datetime import timedelta

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ---------------------------------------------------------------------------
# App factory & configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)

# C1: secret key — env-var with cryptographically random fallback
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("FLASK_SECRET_KEY"):
    logging.warning(
        "FLASK_SECRET_KEY not set; using an ephemeral key. "
        "All sessions will be invalidated on restart."
    )

# C3: debug mode controlled by environment (default OFF)
app.config["DEBUG"] = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")

# M2: secure session-cookie flags
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# SESSION_COOKIE_SECURE can be turned off for local HTTP development
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("FLASK_HTTPS", "true").lower() != "false"
)

# L2: session timeout — 30 minutes of inactivity
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# 文件上传大小限制
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# 允许上传的图片文件后缀
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# ---------------------------------------------------------------------------
# User store — passwords are hashed (C2)
# ---------------------------------------------------------------------------
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password_hash": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------
def init_db():
    """Create the SQLite database and seed default users."""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT
        )
    """)
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) "
        "VALUES ('admin', 'admin123', 'admin@example.com', '13800138000')"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) "
        "VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001')"
    )
    conn.commit()
    conn.close()
    logging.info("Database initialized – data/users.db ready.")

# ---------------------------------------------------------------------------
# CSRF protection (H3)
# ---------------------------------------------------------------------------

def _generate_csrf_token() -> str:
    """Create a CSRF token and persist it in the session."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]


def _validate_csrf(token: str | None) -> bool:
    """Constant-time comparison of the supplied token against the session."""
    stored = session.get("_csrf_token")
    if not stored or not token:
        return False
    return secrets.compare_digest(stored, token)


# Expose the helper to every template so routes don't need to pass it manually.
app.jinja_env.globals["csrf_token"] = _generate_csrf_token

# ---------------------------------------------------------------------------
# Rate limiting (M1)
# ---------------------------------------------------------------------------
_login_attempts: dict[str, list[float]] = defaultdict(list)
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300  # 5 minutes


def _is_rate_limited(ip: str) -> bool:
    """Return True when *ip* has exceeded the allowed login-attempt rate."""
    now = time.time()
    cutoff = now - WINDOW_SECONDS
    _login_attempts[ip] = [t for t in _login_attempts[ip] if t > cutoff]
    return len(_login_attempts[ip]) >= MAX_ATTEMPTS


def _record_attempt(ip: str) -> None:
    """Record a failed login attempt for *ip*."""
    _login_attempts[ip].append(time.time())

# ---------------------------------------------------------------------------
# Input validation (L3)
# ---------------------------------------------------------------------------
_USERNAME_ALLOWED = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_-"
)


def _validate_credentials(username: str, password: str) -> tuple[bool, str | None]:
    """Return (is_valid, error_message)."""
    if not username or not password:
        return False, "用户名和密码不能为空。"
    if len(username) > 32:
        return False, "用户名长度超出限制（最多32个字符）。"
    if len(password) > 128:
        return False, "密码长度超出限制（最多128个字符）。"
    if not username.isprintable() or not password.isprintable():
        return False, "用户名或密码包含无效字符。"
    if not all(c in _USERNAME_ALLOWED for c in username):
        return False, "用户名只能包含字母、数字、下划线和连字符。"
    return True, None

# ---------------------------------------------------------------------------
# Security headers (L1)
# ---------------------------------------------------------------------------

@app.after_request
def _add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'"
    )
    response.headers["Server"] = ""  # don't advertise the stack
    return response

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Home page — shows user info when logged in (H1: never expose password)."""
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        u = USERS[username]
        user_info = {
            "username": u["username"],
            "role": u["role"],
            "email": u["email"],
            "phone": u["phone"],
            "balance": u["balance"],
        }

    # Search functionality
    keyword = request.args.get("keyword", "").strip()
    search_results = None
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        like_pattern = f"%{keyword}%"
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        logging.info(f"[SEARCH SQL] {sql} | keyword={keyword}")
        cursor.execute(sql, (like_pattern, like_pattern))
        search_results = [dict(row) for row in cursor.fetchall()]
        conn.close()

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        keyword=keyword,
        search_results=search_results,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page — PRG, CSRF, rate-limit, input validation, hashed passwords."""
    if request.method == "POST":
        client_ip = request.remote_addr or "127.0.0.1"

        # M1: rate limiting
        if _is_rate_limited(client_ip):
            return (
                render_template("login.html", error="登录尝试过于频繁，请5分钟后再试。"),
                429,
            )

        # H3: CSRF check
        csrf_token = request.form.get("_csrf_token", "")
        if not _validate_csrf(csrf_token):
            _record_attempt(client_ip)
            logging.warning("CSRF token missing or invalid from %s", client_ip)
            return (
                render_template("login.html", error="请求无效，请刷新页面后重试。"),
                400,
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # L3: input validation
        valid, error_msg = _validate_credentials(username, password)
        if not valid:
            _record_attempt(client_ip)
            return render_template("login.html", error=error_msg)

        # C2: authenticate against the password **hash**
        user = USERS.get(username)
        if user and check_password_hash(user["password_hash"], password):
            # H4: prevent session fixation
            session.clear()
            session["username"] = username
            session.permanent = True  # honour PERMANENT_SESSION_LIFETIME
            _generate_csrf_token()    # fresh token for the new session
            logging.info("Login SUCCESS – user=%s ip=%s", username, client_ip)
            flash("登录成功！")
            # M3: PRG pattern — redirect after POST
            return redirect(url_for("index"))

        # Failed login
        _record_attempt(client_ip)
        logging.warning("Login FAILED – user=%s ip=%s", username, client_ip)
        return render_template("login.html", error="用户名或密码错误，请重新输入。")

    # GET — seed a CSRF token so the form can render it
    _generate_csrf_token()
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registration page — uses f-string SQL (deliberately insecure for teaching)."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        logging.info(f"[REGISTER SQL] {sql} | username={username}")
        cursor.execute(sql, (username, password, email, phone))
        conn.commit()
        conn.close()

        flash("注册成功，请登录")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/search")
def search():
    """Search users — uses f-string SQL (deliberately insecure for teaching)."""
    keyword = request.args.get("keyword", "").strip()
    results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        like_pattern = f"%{keyword}%"
        sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
        logging.info(f"[SEARCH SQL] {sql} | keyword={keyword}")
        cursor.execute(sql, (like_pattern, like_pattern))
        results = [dict(row) for row in cursor.fetchall()]
        conn.close()
    return render_template(
        "index.html",
        username=session.get("username"),
        keyword=keyword,
        search_results=results,
    )


@app.route("/logout", methods=["POST"])
def logout():
    """Logout — POST-only with CSRF protection (H5)."""
    csrf_token = request.form.get("_csrf_token", "")
    if not _validate_csrf(csrf_token):
        logging.warning(
            "CSRF token missing or invalid on logout from %s", request.remote_addr
        )
        return redirect(url_for("index"))

    username = session.get("username", "unknown")
    session.clear()
    logging.info("Logout – user=%s ip=%s", username, request.remote_addr)
    return redirect(url_for("index"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """上传头像 — 需要登录才能访问。"""
    username = session.get("username")
    if not username:
        return redirect(url_for("login"))

    if request.method == "POST":
        if "file" not in request.files:
            return render_template("upload.html", error="未选择文件。")

        file = request.files["file"]
        if file.filename == "":
            return render_template("upload.html", error="未选择文件。")

        # 修复1：路径穿越 — 清洗文件名，剥离 ../ 等路径成分
        filename = secure_filename(file.filename)
        if filename == "":
            return render_template("upload.html", error="无效的文件名。")

        # 修复2：文件类型限制 — 仅允许图片后缀
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            return render_template(
                "upload.html",
                error=f"不支持的文件类型（.{ext}），请上传图片文件（png, jpg, jpeg, gif, webp）。",
            )

        # 修复3：文件覆盖 — UUID 前缀确保文件名唯一
        unique_filename = f"{uuid.uuid4().hex}_{filename}"

        upload_dir = os.path.join("static", "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        filepath = os.path.join(upload_dir, unique_filename)
        file.save(filepath)

        file_url = url_for("static", filename=f"uploads/{unique_filename}")
        logging.info("Upload SUCCESS – user=%s file=%s", username, unique_filename)
        return render_template("upload.html", success=True, file_url=file_url, filename=unique_filename)

    return render_template("upload.html")


# ---------------------------------------------------------------------------
# Entry-point (C3: safe defaults)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(debug=app.config["DEBUG"], host=host, port=port)
