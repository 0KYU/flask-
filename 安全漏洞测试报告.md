# flask用户管理系统安全漏洞测试报告

## 报告概要

| 项目 | 内容 |
|------|------|
| 目标 URL | `http://127.0.0.1:5000` |
| 测试时间 | 2026-07-07 19:47 ~ 19:56 (UTC+8) |
| 测试工具 | BurpSuite Pro (MCP 协议自动化控制) |
| 应用服务器 | Werkzeug/3.1.4 Python/3.14.2 |
| 应用框架 | Flask (Debug Mode) |
| 漏洞总数 | **10 个** (🔴严重: 0, 🟡高危: 3, 🟠中危: 5, 🟢低危: 2) |
| 测试结果 | 成功获取有效凭据 (alice/alice2025)，发现多项信息泄露与认证缺陷 |

---

## 漏洞详情

### V-01: HTML 注释泄露默认凭据

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-01 |
| 漏洞名称 | HTML 注释泄露默认管理员凭据 |
| 严重程度 | 🟡高危 |
| CWE 编号 | CWE-200 |
| CVSS 评分 | 7.5 |
| 漏洞描述 | 登录页面 `/login` 的 HTML 源代码中包含注释，直接泄露了默认管理员账号和密码。攻击者只需查看页面源代码即可获取凭据。 |
| 复现步骤 | 1. 访问 `http://127.0.0.1:5000/login` 2. 查看页面 HTML 源代码 3. 发现注释：`<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->` |
| 受影响 URL | `http://127.0.0.1:5000/login` |
| 风险分析 | 攻击者无需任何前置条件即可获取管理员凭据。虽然测试发现该凭据已失效（密码可能已被修改），但该注释仍暴露了系统默认配置和用户名枚举信息。如果存在其他使用相同默认密码的系统组件，攻击者可横向扩展。 |
| 修复建议 | 删除所有 HTML 注释中的敏感信息。如果需要在开发阶段共享测试凭据，应使用安全的内部文档或环境变量管理。 |

```python
# 修复：删除注释中的凭据信息
# 错误做法：
# <!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->

# 正确做法：通过环境变量或配置文件管理默认凭据
import os
DEFAULT_ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME')
DEFAULT_ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
```

---

### V-02: 登录后密码明文回显

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-02 |
| 漏洞名称 | 用户仪表盘明文回显密码 |
| 严重程度 | 🟡高危 |
| CWE 编号 | CWE-200 |
| CVSS 评分 | 6.5 |
| 漏洞描述 | 用户成功登录后，仪表盘页面直接以明文形式显示用户密码。测试中使用 alice/alice2025 登录，页面显示 `密码：alice2025`。 |
| 复现步骤 | 1. POST `http://127.0.0.1:5000/login` 发送 `username=alice&password=alice2025` 2. 查看返回的仪表盘页面 3. 发现明文密码 `密码：alice2025` |
| 受影响 URL | `http://127.0.0.1:5000/` (已登录状态) |
| 风险分析 | 任何能够访问用户会话的人（包括浏览器历史记录查看者、屏幕共享观察者、XSS 攻击者）都能直接看到用户密码。若结合 XSS 漏洞，可批量窃取所有登录用户的密码。 |
| 修复建议 | 仪表盘页面不应显示密码。如需提供用户信息摘要，只显示非敏感字段（如用户名、角色、最后登录时间）。 |

```python
# 修复：仪表盘不显示密码
DASHBOARD_HTML = '''
<h2>Welcome, {username}!</h2>
<p>Role: {role}</p>
<p>Last login: {last_login}</p>
<!-- 删除以下行：<p>Your password: {password}</p> -->
'''
```

---

### V-03: 密码明文传输

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-03 |
| 漏洞名称 | 登录密码通过 HTTP 明文传输 |
| 严重程度 | 🟡高危 |
| CWE 编号 | CWE-319 |
| CVSS 评分 | 7.4 |
| 漏洞描述 | 用户登录时，密码以明文形式在 HTTP POST 请求体中传输，未使用 HTTPS 加密。任何处于同一网络的中间人攻击者都可以截获用户凭据。 |
| 复现步骤 | 1. 在 BurpSuite 中查看 POST /login 请求 2. 请求体为 `username=alice&password=alice2025` 3. 密码以完全可读的明文形式传输 |
| 受影响 URL | `http://127.0.0.1:5000/login` |
| 风险分析 | 在同一网络环境（公共 Wi-Fi、公司内网）中，攻击者可通过 ARP 欺骗、DNS 劫持等方式截获所有 HTTP 流量，直接读取用户名和密码。密码明文传输也意味着任何日志系统（代理、负载均衡器）都可能意外记录密码。 |
| 修复建议 | 1. 部署 HTTPS（TLS 1.2+）证书 2. 强制所有流量跳转到 HTTPS 3. 设置 HSTS 响应头 4. 对密码进行前端哈希后再传输（加盐） |

```nginx
# Nginx 配置示例：强制 HTTPS
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

---

### V-04: 密码明文存储

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-04 |
| 漏洞名称 | 用户密码以明文形式存储 |
| 严重程度 | 🟡高危 |
| CWE 编号 | CWE-312 |
| CVSS 评分 | 7.5 |
| 漏洞描述 | 通过分析源代码 `vuln_app.py`，发现用户密码以明文形式存储在字典中。USERS 字典直接包含 `'admin': 'admin123'`、`'alice': 'alice2025'`、`'bob': 'password123'`。 |
| 复现步骤 | 1. 获取应用源代码 `vuln_app.py` 2. 查看第 15-19 行 USERS 字典 3. 所有密码以明文存储 |
| 受影响 URL | 源代码文件 `vuln_app.py` |
| 风险分析 | 一旦数据库（或源码）泄露，所有用户的密码将完全暴露。用户通常在不同服务间重复使用密码，这会导致凭据填充攻击。不符合 OWASP 密码存储最佳实践。 |
| 修复建议 | 使用安全的密码哈希算法（bcrypt、argon2id、PBKDF2）对密码进行加盐哈希存储。 |

```python
# 修复：使用 bcrypt 哈希存储密码
import bcrypt

# 存储密码时
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# 验证密码时
if bcrypt.checkpw(input_password.encode('utf-8'), stored_hash):
    # 密码正确
    pass
```

---

### V-05: 无登录频率限制

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-05 |
| 漏洞名称 | 登录接口缺少暴力破解防护 |
| 严重程度 | 🟠中危 |
| CWE 编号 | CWE-307 |
| CVSS 评分 | 5.3 |
| 漏洞描述 | `/login` 接口对登录尝试没有任何频率限制、验证码、账户锁定或 IP 限制。攻击者可以进行无限次数的密码尝试。 |
| 复现步骤 | 1. 向 `/login` 连续发送多个不同密码的 POST 请求 2. 观察到所有请求均得到正常响应，无任何限制 3. BurpSuite Intruder 可进行高速密码爆破 |
| 受影响 URL | `http://127.0.0.1:5000/login` |
| 风险分析 | 攻击者可通过字典攻击或暴力破解获取用户密码。本次测试中通过有限尝试就发现了有效的 alice/alice2025 凭据。在生产环境中，这种漏洞会导致账户接管。 |
| 修复建议 | 1. 实现基于 IP 和用户名的登录频率限制（如 5 次/分钟） 2. 多次失败后要求验证码 3. N 次失败后临时锁定账户 4. 添加登录延迟（递增等待时间） |

```python
# 修复：使用 Flask-Limiter 实现速率限制
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(app, key_func=get_remote_address)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # 每分钟最多 5 次
def login():
    # 登录逻辑
    pass
```

---

### V-06: 无会话超时机制

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-06 |
| 漏洞名称 | 会话 Cookie 无过期时间 |
| 严重程度 | 🟠中危 |
| CWE 编号 | CWE-613 |
| CVSS 评分 | 4.8 |
| 漏洞描述 | 登录成功后设置的 session cookie (`session=eyJ...`) 未设置 `Expires` 或 `Max-Age` 属性，会话永不过期。 |
| 复现步骤 | 1. 使用 alice 凭据登录 2. 检查 Set-Cookie 响应头：`session=eyJ...; HttpOnly; Path=/` 3. 缺少 Expires/Max-Age 属性 |
| 受影响 URL | `http://127.0.0.1:5000/login` (Set-Cookie 响应) |
| 风险分析 | 1. 会话令牌永不过期，一旦泄露可被永久利用 2. 用户关闭浏览器后 cookie 仍有效（取决于浏览器策略） 3. 无法强制用户定期重新认证 |
| 修复建议 | 设置合理的会话超时时间，同时支持绝对超时和空闲超时。 |

```python
# 修复：设置会话超时
from datetime import datetime, timedelta

# 会话存储中加入过期时间
sessions[session_id] = {
    'username': username,
    'created_at': datetime.now(),
    'expires_at': datetime.now() + timedelta(hours=2)
}

# 响应中设置 Max-Age
resp.set_cookie(
    'session_id', session_id,
    max_age=7200,  # 2 小时
    httponly=True,
    secure=True,   # 仅 HTTPS
    samesite='Lax'
)
```

---

### V-07: 缺乏安全响应头

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-07 |
| 漏洞名称 | 应用未设置关键 HTTP 安全响应头 |
| 严重程度 | 🟠中危 |
| CWE 编号 | CWE-693 |
| CVSS 评分 | 5.0 |
| 漏洞描述 | 所有响应均缺少关键的安全响应头，包括 CSP、X-Frame-Options、X-Content-Type-Options、Referrer-Policy、Permissions-Policy 等。 |
| 复现步骤 | 1. 发送任意请求到 `http://127.0.0.1:5000` 2. 检查响应头 3. 仅有 `Server: Werkzeug/3.1.4 Python/3.14.2`、`Content-Type` 和 `Vary`，无安全相关头 |
| 受影响 URL | 全部响应 |
| 风险分析 | 缺乏安全响应头使应用暴露于多种客户端攻击：Clickjacking（缺 X-Frame-Options）、MIME 嗅探攻击（缺 X-Content-Type-Options）、XSS 和数据注入（缺 CSP）、信息泄露（缺 Referrer-Policy）。 |
| 修复建议 | 在所有响应中添加以下安全头： |

```python
# 修复：Flask 添加安全响应头
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=()'
    response.headers['Server'] = ''  # 隐藏服务器信息
    return response
```

---

### V-08: Debug 模式生产环境开启

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-08 |
| 漏洞名称 | Flask 应用以 Debug 模式运行 |
| 严重程度 | 🟠中危 |
| CWE 编号 | CWE-489 |
| CVSS 评分 | 5.5 |
| 漏洞描述 | 应用服务器响应头显示 `Server: Werkzeug/3.1.4 Python/3.14.2`，源代码确认 `app.debug = True`。Debug 模式在生产环境中极度危险，Werkzeug 调试器允许在错误页面执行任意 Python 代码。 |
| 复现步骤 | 1. 观察服务器响应头 `Server: Werkzeug/3.1.4 Python/3.14.2` 2. 查看源码第 11 行 `app.debug = True` 3. 若触发未处理异常，Werkzeug 调试器将暴露交互式 Python shell |
| 受影响 URL | 全局配置 |
| 风险分析 | 1. Werkzeug 调试器的交互式控制台允许远程执行任意代码 2. 错误页面会泄露完整源码上下文 3. 每次请求会消耗额外内存（重载器监控） 4. 性能下降 |
| 修复建议 | 生产环境必须关闭 Debug 模式。 |

```python
# 修复：通过环境变量控制
import os

app.debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

# 或使用 Flask 配置
app.config['DEBUG'] = False
app.config['ENV'] = 'production'
```

---

### V-09: Session Token 编码用户名泄露

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-09 |
| 漏洞名称 | Session Cookie 以 Base64 编码泄露用户名 |
| 严重程度 | 🟠中危 |
| CWE 编号 | CWE-200 |
| CVSS 评分 | 4.3 |
| 漏洞描述 | Session cookie 的第一部分是 Base64 编码的 JSON 数据，直接包含用户名。解码 `eyJ1c2VybmFtZSI6ImFsaWNlIn0` 得到 `{"username":"alice"}`。任何人都可从 cookie 中解码出用户名。 |
| 复现步骤 | 1. 登录后获取 session cookie 2. 提取第一部分：`eyJ1c2VybmFtZSI6ImFsaWNlIn0` 3. Base64 解码得到 `{"username":"alice"}` |
| 受影响 URL | 所有带 session cookie 的请求 |
| 风险分析 | 1. 攻击者可从流量中识别用户身份 2. 暴露了 session 的内部结构，降低了逆向工程难度 3. 若签名算法存在缺陷，可被用于伪造 session |
| 修复建议 | 1. Session 数据应使用加密而非仅编码 2. 使用 Flask 内置的 `itsdangerous` 签名 session（Flask 默认 session 是安全的） 3. 不要在客户端可解码的数据中存放敏感信息 |

```python
# 修复：使用 Flask 内置加密 session
from flask import session

app.secret_key = os.urandom(24).hex()  # 从环境变量读取

@app.route('/login', methods=['POST'])
def login():
    # ...
    session['username'] = username
    session['role'] = role
    # Flask 会自动签名和加密 session cookie
```

---

### V-10: 未授权访问泄露系统信息

| 字段 | 内容 |
|------|------|
| 漏洞编号 | V-10 |
| 漏洞名称 | 未认证首页泄露系统状态信息 |
| 严重程度 | 🟢低危 |
| CWE 编号 | CWE-200 |
| CVSS 评分 | 3.7 |
| 漏洞描述 | 在未登录状态下访问首页 `/`，页面显示 `System Status: Online | Users: 3`，泄露了系统用户数量和运行状态。同时泄露服务器为 Werkzeug/3.1.4 Python/3.14.2。 |
| 复现步骤 | 1. GET `http://127.0.0.1:5000/`（不带 Cookie） 2. 页面显示用户总数和系统状态 |
| 受影响 URL | `http://127.0.0.1:5000/` |
| 风险分析 | 暴露用户总数可以帮助攻击者评估攻击价值、进行用户名枚举。服务器版本信息可用于寻找已知漏洞（如特定版本 Werkzeug 的 CVE）。 |
| 修复建议 | 1. 不在未认证页面显示系统内部信息 2. 移除或模糊化 Server 响应头 3. 将首页重定向到登录页 |

---

## 漏洞汇总表

| 编号 | 漏洞名称 | CWE | 严重程度 | CVSS | 状态 |
|------|---------|------|---------|------|------|
| V-01 | HTML 注释泄露默认凭据 | CWE-200 | 🟡高危 | 7.5 | 已确认 |
| V-02 | 登录后密码明文回显 | CWE-200 | 🟡高危 | 6.5 | 已确认 |
| V-03 | 密码明文传输 | CWE-319 | 🟡高危 | 7.4 | 已确认 |
| V-04 | 密码明文存储 | CWE-312 | 🟡高危 | 7.5 | 已确认(源码) |
| V-05 | 无登录频率限制 | CWE-307 | 🟠中危 | 5.3 | 已确认 |
| V-06 | 无会话超时机制 | CWE-613 | 🟠中危 | 4.8 | 已确认 |
| V-07 | 缺乏安全响应头 | CWE-693 | 🟠中危 | 5.0 | 已确认 |
| V-08 | Debug 模式开启 | CWE-489 | 🟠中危 | 5.5 | 已确认(源码) |
| V-09 | Session Token 用户信息泄露 | CWE-200 | 🟠中危 | 4.3 | 已确认 |
| V-10 | 未授权访问泄露系统信息 | CWE-200 | 🟢低危 | 3.7 | 已确认 |

---

## 已测试且未发现漏洞的项目

| 测试项 | 测试方法 | 结果 |
|--------|----------|------|
| SQL 注入 | `admin' OR '1'='1`、`admin'+OR+1=1--`、URL 编码变体 | 未成功 - 应用使用了字典匹配而非 SQL 查询 |
| 路径遍历 | `/static/../app.py`、`/static/../templates/index.html` | 被 Werkzeug 阻止 - 返回 404 |
| Session 伪造 | 修改 Base64 编码的用户名部分 | 签名验证阻止了伪造 |
| Session 固定 | 使用固定 Cookie 值登录 | 无法确认（服务器响应异常） |

---

## 风险评分统计

```
严重程度分布:
🔴 严重: 0
🟡 高危: 4  (V-01, V-02, V-03, V-04)
🟠 中危: 5  (V-05, V-06, V-07, V-08, V-09)
🟢 低危: 1  (V-10)

平均 CVSS: 5.85
最高 CVSS: 7.5 (V-01, V-04)
```

---

## 修复优先级建议

1. **立即修复 (P0)**: V-01 (删除 HTML 注释)、V-04 (密码哈希存储)
2. **尽快修复 (P1)**: V-02 (移除密码回显)、V-03 (启用 HTTPS)、V-08 (关闭 Debug)
3. **计划修复 (P2)**: V-05 (添加速率限制)、V-06 (会话超时)、V-07 (安全响应头)
4. **建议修复 (P3)**: V-09 (加密 session)、V-10 (隐藏系统信息)

---

*报告生成时间: 2026-07-07 19:56 (UTC+8)*
*测试工具: BurpSuite Pro via MCP Protocol*
