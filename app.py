import logging
import os
import sqlite3
import secrets
import time
import uuid
from collections import defaultdict
import urllib.request
import urllib.error
import urllib.parse
import ipaddress
import socket
import re
import json
import subprocess
import platform
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

# 允许加载的页面名称白名单（FI-1修复：第1层防线 — 白名单校验）
ALLOWED_PAGES = {"help"}

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
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    # 兼容已存在的数据库：添加 balance 列（如果不存在）
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # 列已存在
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone, balance) "
        "VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 99999)"
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone, balance) "
        "VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 100)"
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
# Auth helpers
# ---------------------------------------------------------------------------


def _require_login():
    """若未登录返回 None；已登录返回 USERS 字典中的用户信息。"""
    username = session.get("username")
    if not username or username not in USERS:
        return None
    return USERS[username]


def _is_ssrf_safe(url):
    """SSRF 防护：校验 URL 方案 + 解析 DNS 并阻止内网 IP。
    返回 (is_safe, error_message)。
    """
    # 第1层：URL 解析
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "无法解析 URL。"

    # 第2层：协议白名单（仅允许 http/https）
    if parsed.scheme not in ("http", "https"):
        return False, f"不支持的协议: {parsed.scheme}。仅允许 http/https。"

    # 第3层：提取主机名
    hostname = parsed.hostname
    if not hostname:
        return False, "无法从 URL 中提取主机名。"

    # 第4层：阻止 localhost 别名
    if hostname.lower() in ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "::1"):
        return False, "不允许访问本地回环地址。"

    # 第5层：DNS 解析 + IP 过滤
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False, f"无法解析主机名: {hostname}。"
    except Exception as e:
        return False, f"DNS 解析失败: {e}。"

    # 提取所有解析到的 IP
    resolved_ips = set()
    for info in addr_info:
        addr = info[4][0]
        resolved_ips.add(addr)

    # 第6层：IP 地址黑白名单
    for addr in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if ip_obj.is_loopback:
            return False, f"不允许访问回环地址: {addr}。"
        if ip_obj.is_private:
            return False, f"不允许访问内网地址: {addr}。"
        if ip_obj.is_link_local:
            return False, f"不允许访问链路本地地址: {addr}。"

    return True, None


def _is_safe_ping_target(target):
    """命令注入防护：校验 ping 目标是否为合法的 IP 或主机名。
    返回 (is_safe, error_message)。
    """
    if not target or len(target) > 253:
        return False, "目标为空或长度超过 253 字符。"

    # 白名单正则：IPv4、简单主机名/域名（字母数字+连字符+点）
    # 单字符主机名、IPv6（含冒号和方括号）
    pattern = r'^[a-zA-Z0-9][-a-zA-Z0-9.:\[\]]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$|^[a-fA-F0-9:]+$'
    if not re.match(pattern, target):
        return False, f"目标格式不合法: {target}"

    # 额外检查：拒绝所有常见的 shell 元字符和命令分隔符
    dangerous = {';', '&&', '||', '|', '&', '$', '`', '(', ')', '{', '}', '#', '!', '<', '>', '\n', '\r', '\t', "'", '"', '\\'}
    for char in dangerous:
        if char in target:
            return False, f"目标包含非法字符: {char}"

    return True, None


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
            # 从数据库获取 user_id 存入 session（供导航链接使用）
            conn = sqlite3.connect("data/users.db")
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            row = cur.fetchone()
            if row:
                session["user_id"] = row[0]
            conn.close()
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


@app.route("/profile")
def profile():
    """个人中心 — 需登录，仅可查看本人资料或 admin 可查看他人。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    user_id = request.args.get("user_id", "").strip()
    user = None
    error = None

    # IDOR 修复：非本人且非 admin 拒绝访问
    if user_id and str(session.get("user_id")) != user_id and current_user["role"] != "admin":
        return render_template(
            "profile.html",
            username=session.get("username"),
            user=user,
            error="无权查看其他用户的资料。",
        ), 403

    if not user_id:
        error = "缺少用户 ID 参数。"
    else:
        conn = sqlite3.connect("data/users.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, phone, balance FROM users WHERE id = ?",
            (user_id,),
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            user = dict(row)
        else:
            error = f"用户 ID {user_id} 不存在。"

    return render_template(
        "profile.html",
        username=session.get("username"),
        user=user,
        error=error,
        user_id=user_id,
    )


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 — 需登录，CSRF 保护，服务端校验金额，user_id 从 session 获取。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    # CSRF 校验
    csrf_token = request.form.get("_csrf_token", "")
    if not _validate_csrf(csrf_token):
        logging.warning(
            "CSRF token missing or invalid on recharge from %s", request.remote_addr
        )
        flash("请求无效，请刷新页面后重试。")
        return redirect(url_for("index"))

    # user_id 从 session 获取，不信任表单字段；admin 可为他人充值
    user_id = str(session.get("user_id"))
    if current_user["role"] == "admin" and request.form.get("user_id"):
        user_id = request.form.get("user_id", "").strip()

    # 服务端校验金额
    try:
        amount = float(request.form.get("amount", "0"))
    except (ValueError, TypeError):
        flash("无效的金额。")
        return redirect(f"/profile?user_id={user_id}")
    if amount <= 0:
        flash("充值金额必须大于 0。")
        return redirect(f"/profile?user_id={user_id}")
    if amount > 10000:
        flash("单次充值金额不能超过 10000。")
        return redirect(f"/profile?user_id={user_id}")

    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, user_id),
    )
    conn.commit()
    conn.close()

    logging.info(
        "Recharge – user_id=%s amount=%s",
        user_id,
        amount,
    )
    flash(f"充值成功！金额：{amount}")
    return redirect(f"/profile?user_id={user_id}")


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 需登录，无需原密码验证，无需 CSRF。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    # CSRF 校验
    csrf_token = request.form.get("_csrf_token", "")
    if not _validate_csrf(csrf_token):
        logging.warning(
            "CSRF token missing or invalid on password change from %s", request.remote_addr
        )
        flash("请求无效，请刷新页面后重试。")
        return redirect(url_for("index"))

    username = request.form.get("username", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    # 基本校验
    if not username or not new_password:
        flash("用户名和新密码不能为空。")
        return redirect(url_for("profile"))

    if new_password != confirm_password:
        flash("两次输入的密码不一致。")
        return redirect(url_for("profile"))

    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (new_password, username),
    )
    conn.commit()
    conn.close()

    logging.info(
        "Password changed – username=%s by=%s",
        username,
        session.get("username"),
    )
    flash(f"用户 {username} 的密码修改成功！")
    return redirect(url_for("profile"))


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取 — 需登录，不对 URL 做任何限制（SSRF 教学用途）。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    url = request.form.get("url", "").strip()
    if not url:
        flash("请输入要抓取的 URL。")
        return redirect(url_for("index"))

    # SSRF 防护
    safe, ssrf_error = _is_ssrf_safe(url)
    if not safe:
        logging.warning(
            "SSRF blocked – url=%s reason=%s from=%s",
            url, ssrf_error, request.remote_addr,
        )
        return render_template(
            "index.html",
            username=session.get("username"),
            fetch_url=url,
            fetch_error=ssrf_error,
        )

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Flask-Fetcher/1.0"})
        with urllib.request.urlopen(req, timeout=10) as response:
            status_code = response.status
            body = response.read().decode("utf-8", errors="replace")[:5000]
        return render_template(
            "index.html",
            username=session.get("username"),
            fetch_url=url,
            fetch_status=status_code,
            fetch_result=body,
        )
    except urllib.error.URLError as e:
        return render_template(
            "index.html",
            username=session.get("username"),
            fetch_url=url,
            fetch_error=f"网络错误: {e.reason}",
        )
    except Exception as e:
        return render_template(
            "index.html",
            username=session.get("username"),
            fetch_url=url,
            fetch_error=f"抓取失败: {str(e)}",
        )


@app.route("/ping", methods=["GET", "POST"])
def ping_test():
    """Ping 网络诊断 — 需登录。GET 显示页面，POST 执行 ping 命令。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("ping.html", username=session.get("username"))

    # CSRF 保护
    if not _validate_csrf(request.form.get("_csrf_token", "")):
        flash("请求无效，请刷新页面后重试。")
        return redirect(url_for("ping_test"))

    # POST: 执行 ping 命令
    ip = request.form.get("ip", "").strip()
    if not ip:
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_error="请输入 IP 地址或域名。",
        )

    # 命令注入防护：校验目标地址
    safe, safe_error = _is_safe_ping_target(ip)
    if not safe:
        logging.warning(
            "Ping command injection blocked – target=%s reason=%s from=%s",
            ip, safe_error, request.remote_addr,
        )
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_ip=ip,
            ping_error=safe_error,
        )

    # 根据操作系统选择 ping 参数
    param = "-n" if platform.system().lower() == "windows" else "-c"

    try:
        output = subprocess.check_output(["ping", param, "3", ip], shell=False, timeout=30, stderr=subprocess.STDOUT)
        result = output.decode("utf-8", errors="replace")
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_ip=ip,
            ping_result=result,
        )
    except subprocess.CalledProcessError as e:
        result = e.output.decode("utf-8", errors="replace") if e.output else str(e)
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_ip=ip,
            ping_error=result,
        )
    except subprocess.TimeoutExpired:
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_ip=ip,
            ping_error="Ping 命令执行超时（30 秒）。",
        )
    except Exception as e:
        return render_template(
            "ping.html",
            username=session.get("username"),
            ping_ip=ip,
            ping_error=f"执行失败: {str(e)}",
        )


@app.route("/admin")
def admin_panel():
    """管理面板 — 仅 admin 角色可访问，列出所有用户。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))
    if current_user["role"] != "admin":
        return render_template("admin.html", error="无权访问管理面板。"), 403

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, phone, balance FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template(
        "admin.html",
        username=session.get("username"),
        users=users,
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


@app.route("/page")
def page():
    """Dynamic page loader — reads HTML files from pages/ directory.

    Security (FI-1/FI-2/FI-3 fix — 3-layer defense-in-depth):
      Layer 1: Page-name whitelist    — only known pages are allowed
      Layer 2: Path sanitization      — secure_filename strips ../ and separators
      Layer 3: Directory confinement  — realpath must stay inside pages/ directory
      Auth gate: login required       — prevents unauthenticated file access (FI-2)
    """
    # 认证检查（FI-2修复）：要求登录后才能访问页面
    if not _require_login():
        flash("请先登录后再访问页面。")
        return redirect(url_for("index"))

    name = request.args.get("name", "")
    page_content = None
    page_error = None

    if name:
        # ---------------------------------------------------------------
        # 第1层防线（FI-1修复）：页面名称白名单校验
        # 仅允许 ALLOWED_PAGES 集合中的页面名称
        # ---------------------------------------------------------------
        # 先尝试剥离 .html 后缀做白名单匹配
        check_name = name
        if check_name.endswith(".html"):
            check_name = check_name[:-5]

        if check_name not in ALLOWED_PAGES:
            logging.warning(f"[PAGE] Rejected by whitelist — name={name}")
            page_error = "页面不存在"

        if not page_error:
            # ---------------------------------------------------------------
            # 第2层防线（FI-1修复）：路径安全化
            # 使用 secure_filename 剥离 ../、/、\、.. 等路径分隔符
            # ---------------------------------------------------------------
            safe_name = secure_filename(name)
            if not safe_name.endswith(".html"):
                safe_name = safe_name + ".html"

            # ---------------------------------------------------------------
            # 第3层防线（FI-1修复）：目录 confinement
            # 使用 realpath 解析真实路径，确保结果在 pages/ 目录内
            # ---------------------------------------------------------------
            pages_dir = os.path.realpath("pages")
            filepath = os.path.realpath(os.path.join("pages", safe_name))

            if not filepath.startswith(pages_dir + os.sep):
                logging.warning(
                    f"[PAGE] Path traversal blocked — name={name} resolved={filepath}"
                )
                page_error = "页面不存在"
            elif os.path.isfile(filepath):
                with open(filepath, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_error = "页面不存在"

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

    return render_template(
        "index.html",
        username=username,
        user=user_info,
        keyword="",
        search_results=None,
        page_content=page_content,
        page_error=page_error,
    )


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """XML导入 — 需登录。GET 显示页面，POST 处理XML数据导入。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    if request.method == "GET":
        return render_template("xml_import.html", username=session.get("username"))

    # CSRF 保护
    if not _validate_csrf(request.form.get("_csrf_token", "")):
        flash("请求无效，请刷新页面后重试。")
        return redirect(url_for("xml_import"))

    # POST: 处理 XML 数据
    xml_data = request.form.get("xml_data", "").strip()
    if not xml_data:
        return render_template(
            "xml_import.html",
            username=session.get("username"),
            error="请输入XML数据。",
        )

    # 使用 defusedxml 安全解析 XML
    # defusedxml 自动禁用外部实体、DTD 和实体展开，防止 XXE 攻击
    import defusedxml.ElementTree as SafeET

    try:
        root = SafeET.fromstring(xml_data)

        # 提取 user 节点 (name, email)
        users = []
        for user_elem in root.findall(".//user"):
            name_elem = user_elem.find("name")
            email_elem = user_elem.find("email")
            user = {
                "name": name_elem.text if name_elem is not None else None,
                "email": email_elem.text if email_elem is not None else None,
            }
            users.append(user)

        if not users:
            return render_template(
                "xml_import.html",
                username=session.get("username"),
                xml_data=xml_data,
                error="未在XML中找到user节点。",
            )

        result = {"users": users}
        result_json = json.dumps(result, ensure_ascii=False, indent=2)
        return render_template(
            "xml_import.html",
            username=session.get("username"),
            xml_data=xml_data,
            result=result_json,
        )

    except (SafeET.ParseError, Exception) as e:
        # 识别 defusedxml 拦截的外部实体攻击
        exc_name = type(e).__name__
        if exc_name == "EntitiesForbidden":
            error_msg = f"XML包含禁止的外部实体引用，XXE 攻击已被拦截。"
        elif "Forbidden" in exc_name or exc_name == "DTDForbidden":
            error_msg = f"XML安全解析失败: {str(e)}"
        elif exc_name == "ParseError":
            error_msg = f"XML解析错误: {str(e)}"
        else:
            error_msg = f"处理失败: {str(e)}"

        error_json = json.dumps(
            {"error": error_msg}, ensure_ascii=False, indent=2
        )
        return render_template(
            "xml_import.html",
            username=session.get("username"),
            xml_data=xml_data,
            error=error_json,
        )


# ---------------------------------------------------------------------------
# Entry-point (C3: safe defaults)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(debug=app.config["DEBUG"], host=host, port=port)
