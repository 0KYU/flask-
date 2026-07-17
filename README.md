# Flask 用户管理系统 🔐

基于 Flask 框架构建的 Web 用户管理系统，提供登录认证、用户注册、搜索、头像上传、个人中心、充值等核心功能。项目经历了**从漏洞百出到逐步加固**的完整安全演进过程。

## 📖 项目演进历程

### 初始版本 — 未检测的原始状态

项目最初是一个基础的 Flask 登录应用，采用最简单的实现方式，存在大量安全隐患，包括：

- 硬编码密钥、明文密码存储、无 CSRF 防护、无速率限制、无安全响应头、无输入校验等共计 **16 项安全漏洞**。

### DAY2 — 安全漏洞全面修复

对初始版本进行了完整的安全审计与渗透测试，逐一识别并修复了全部 **16 项安全漏洞**（3 严重 / 5 高危 / 3 中危 / 5 低危），建立了三层纵深防御体系：

| 防线 | 涵盖漏洞 | 核心机制 |
|------|---------|---------|
| 🛡️ **密码学安全** | 硬编码密钥、明文密码 | 环境变量密钥 + bcrypt 哈希 |
| 🔐 **会话与认证安全** | CSRF、Session 固定、速率限制、Cookie 标志、PRG | CSRF Token + Session 重生 + IP 滑动窗口 |
| 📋 **输入/输出安全** | 密码泄露、安全响应头、输入校验、审计日志 | 脱敏渲染 + CSP/X-Frame-Options + 白名单校验 + logging |

> 📄 详细内容见 [DAY2-安全漏洞测试与修复报告.md](DAY2-安全漏洞测试与修复报告.md)

### DAY3 — 功能扩展与 SQL 注入攻防

在已加固的登录系统基础上，新增了**用户注册**和**用户搜索**功能，引入 SQLite 数据库。新增功能为教学目的使用了不安全的 SQL 拼接方式，随后进行了专项漏洞检测与修复。

#### 新增功能

- **用户注册** (`/register`) — 注册信息写入 SQLite 数据库
- **用户搜索** (`/`、`/search`) — 按用户名/邮箱模糊搜索
- **数据库** — SQLite `data/users.db`，启动时自动初始化

#### SQL 注入漏洞检测

对新增接口进行了专项 SQL 注入渗透测试，发现 **2 个高危注入点**：

| 漏洞 | 接口 | 攻击方式 | 危害 |
|------|------|----------|------|
| SQL-1 | `/search`、`/` | UNION 联合查询注入 | 提取全部用户密码 + 数据库 Schema |
| SQL-2 | `/register` | INSERT 语句注入 | 批量创建用户，绕过注册限制 |

#### SQL 注入修复

将 3 处 f-string 字符串拼接 SQL 全部改为 `?` 占位符参数化查询，从根源消除注入风险。

> 📄 详细内容见 [DAY3-SQL注入漏洞测试与修复报告.md](DAY3-SQL注入漏洞测试与修复报告.md)

### DAY4 — 文件上传功能与安全攻防

在已有登录、注册、搜索功能基础上，新增了**用户头像上传**功能。初始实现为教学目的跳过了所有安全检查，随后进行了专项漏洞检测与修复。

#### 新增功能

- **头像上传** (`/upload`) — 登录用户可上传头像图片，支持预览和链接访问
- **上传目录** — `static/uploads/`，文件通过 Web 直接访问

#### 文件上传漏洞检测

对上传接口进行了专项安全测试，发现 **3 个安全漏洞**：

| 漏洞 | CWE | 成因 | 攻击方式 | 危害 |
|------|-----|------|----------|------|
| UPL-1 | CWE-22 | `file.filename` 直接拼接路径 | `../` 路径穿越 | 文件写入任意目录（含用户 Home 目录） |
| UPL-2 | CWE-434 | 无文件类型检查 | 上传 HTML 文件 | XSS 攻击，窃取同源 Cookie/Session |
| UPL-3 | CWE-73 | 原始文件名直接保存 | 同名文件覆盖 | 替换其他用户已上传的头像 |

#### 文件上传漏洞修复

实施三层防御：`secure_filename()` 清洗文件名 + 图片后缀白名单 + UUID 前缀唯一化命名。

> 📄 详细内容见 [DAY4-文件上传漏洞测试与修复报告.md](DAY4-文件上传漏洞测试与修复报告.md)

### DAY5 — 个人中心/充值功能 + 越权漏洞攻防

在已有功能基础上，新增了**个人中心**和**余额充值**功能。新功能为教学目的跳过了所有权限校验，随后参照 PortSwigger Web Security Academy 三类经典实验室漏洞进行了专项检测与修复。

#### 新增功能

- **个人中心** (`/profile`) — 查看用户资料（ID、用户名、邮箱、手机、余额）
- **余额充值** (`/recharge`) — 为账户充值
- **管理面板** (`/admin`) — 管理员查看所有用户列表

#### 越权漏洞检测

参照 PortSwigger 实验室漏洞模型，检测到 **3 类严重安全漏洞**：

| 漏洞 | CWE | CVSS 3.1 | PortSwigger 参考 | 成因 |
|------|-----|----------|-----------------|------|
| 过度信任客户端控制 | CWE-602 | 8.1 HIGH | [Excessive Trust in Client-Side Controls] | `amount` 无校验 + `user_id` 信任表单 + 无 CSRF |
| 未保护的管理功能 | CWE-862 | 7.5 HIGH | [Unprotected Admin Functionality] | admin 角色已定义但从未用于访问控制 |
| 用户 ID 受参数控制 (IDOR) | CWE-639 | 7.5 HIGH | [User ID Controlled by Request Parameter] | `user_id` 从 URL 获取，无所有权验证 |

#### 越权漏洞修复

实施纵深防御：认证检查（`_require_login()`）+ 授权检查（IDOR 防护 + RBAC）+ 输入校验（金额范围 + CSRF Token）。

> 📄 详细内容见 [DAY5-业务逻辑与越权漏洞的测试与修复报告.md](DAY5-业务逻辑与越权漏洞的测试与修复报告.md)

### DAY6 — 动态页面加载功能 + 文件包含漏洞攻防

在已有功能基础上，新增了**动态页面加载**功能。该功能为教学目的未做任何路径校验，随后进行了专项漏洞检测与修复。

#### 新增功能

- **动态页面加载** (`/page`) — 根据 URL 参数 `?name=` 加载 `pages/` 目录下的 HTML 页面并渲染到首页
- **帮助中心** — `pages/help.html`，提供常见问题和联系方式

#### 文件包含漏洞检测

对 `/page` 接口进行了专项安全测试，发现 **3 个安全漏洞**：

| 漏洞 | CWE | CVSS 3.1 | 成因 | 攻击方式 | 危害 |
|------|-----|---------|------|----------|------|
| FI-1 | CWE-22 | 8.6 HIGH | `name` 参数直接拼接到文件路径 | `../` 路径遍历 | 读取 `app.py`、`data/users.db`、`.git/config` 等任意文件 |
| FI-2 | CWE-306 | 7.5 HIGH | `/page` 路由无认证检查 | 未登录直接访问 | 任意访客可发起路径遍历攻击 |
| FI-3 | CWE-79 | 5.4 MEDIUM | `page_content` 使用 `\| safe` 渲染 | 结合文件上传 XSS | 恶意 HTML 内容在浏览器中执行 |

#### 文件包含漏洞修复

实施三层纵深防御：页面名白名单（`ALLOWED_PAGES`）+ `secure_filename()` 路径安全化 + `realpath()` 目录 confinement，外加 `_require_login()` 认证守卫。

> 📄 详细内容见 [DAY6-文件包含漏洞测试与修复报告.md](DAY6-文件包含漏洞测试与修复报告.md)

### DAY7 — 密码修改功能 + CSRF 漏洞攻防

在已有功能基础上，新增了**密码修改**功能。新功能为教学目的跳过了 CSRF 保护，随后进行了专项漏洞检测与修复。

#### 新增功能

- **密码修改** (`/change-password`) — 登录用户可修改任意用户的密码，前端确认密码一致性

#### CSRF 漏洞检测

对 `/change-password` 接口进行了 CSRF 专项测试，发现 **1 个 CSRF 高危漏洞**（附带发现 `/register` 和 `/upload` 同样缺少 CSRF）：

| 漏洞 | CWE | CVSS 3.1 | 成因 | 攻击方式 | 危害 |
|------|-----|---------|------|----------|------|
| CSRF-1 | CWE-352 | 8.1 HIGH | `/change-password` 无 CSRF Token 校验 + 表单无 Token 字段 | 跨站自动提交表单 | 攻击者可修改任意用户密码，结合隐藏 `username` 字段可实现精准账户接管 |

#### CSRF 修复

在 `/change-password` 路由添加 `_validate_csrf()` 校验 + 表单嵌入 `_csrf_token` 隐藏字段。修复后全应用 POST 路由 CSRF 覆盖率从 50%（3/6）提升至 67%（4/6）。

> 📄 详细内容见 [DAY7-CSRF漏洞测试与修复报告.md](DAY7-CSRF漏洞测试与修复报告.md)

### DAY8 — URL 抓取功能 + SSRF 漏洞攻防

在已有功能基础上，新增了**URL 抓取**功能。新功能为教学目的跳过了所有 URL 校验，随后进行了专项 SSRF 漏洞检测与修复。

#### 新增功能

- **URL 抓取** (`/fetch-url`) — 登录用户可提交 URL，服务端代理抓取并回显内容（前 5000 字符）

#### SSRF 漏洞检测

对 `/fetch-url` 接口进行了 SSRF 专项测试，发现 **3 个高危 SSRF 漏洞**：

| 漏洞 | CWE | CVSS 3.1 | 成因 | 攻击方式 | 危害 |
|------|-----|---------|------|----------|------|
| SSRF-1 | CWE-918 | 8.6 HIGH | 无协议限制 | `file:///etc/passwd` | 读取服务器任意本地文件（含源码、数据库） |
| SSRF-2 | CWE-918 | 8.1 HIGH | 无内网 IP 过滤 | `http://127.0.0.1:5000/admin` | 绕过 ACL 访问内网管理面板 |
| SSRF-3 | CWE-918 | 7.5 HIGH | DNS 解析无 IP 验证 | DNS rebinding + 云元数据 | 获取云环境临时凭证（IAM/STS） |

#### SSRF 修复

实施六层纵深防御：URL 解析 → 协议白名单 → 主机名提取 → localhost 黑名单 → DNS 解析 → IP 地址过滤（阻止 loopback/private/link-local）。

> 📄 详细内容见 [DAY8-SSRF漏洞测试与修复报告.md](DAY8-SSRF漏洞测试与修复报告.md)

### DAY9 — Ping 网络诊断功能 + 命令注入攻防

在已有功能基础上，新增了 **Ping 网络诊断**功能。新功能为教学目的使用了 `shell=True` + f-string 拼接的方式构建系统命令且未过滤输入，随后进行了专项命令注入漏洞检测与修复。

#### 新增功能

- **Ping 网络诊断** (`/ping`) — 登录用户可输入 IP 地址或域名，执行 ping 连通性测试，结果以终端风格展示

#### 命令注入漏洞检测

对 `/ping` 接口进行了命令注入和 CSRF 专项测试，发现 **3 个安全漏洞**：

| 漏洞 | CWE | CVSS 3.1 | 成因 | 攻击方式 | 危害 |
|------|-----|---------|------|----------|------|
| CMDI-1 | CWE-77 | 8.8 HIGH | `shell=True` + f-string 未过滤拼接 | `127.0.0.1 && whoami` | 任意系统命令执行（读/写/删文件、反弹 shell） |
| CMDI-2 | CWE-77 | 7.5 HIGH | 未过滤 shell 元字符（`;` `\|` `\|\|` `&&` `$()` 等） | 多种分隔符绕过 | 即使过滤分号也无法防御 |
| CMDI-3 | CWE-352 | 5.4 MEDIUM | `/ping` POST 路由缺少 CSRF 保护 | 外部页面自动提交表单 | 结合命令注入可扩大攻击面 |

#### 命令注入修复

实施四层纵深防御：认证守卫 → CSRF Token 校验 → 输入白名单+元字符黑名单 (`_is_safe_ping_target()`) → `shell=False` 参数列表执行。

> 📄 详细内容见 [DAY9-命令注入漏洞测试与修复报告.md](DAY9-命令注入漏洞测试与修复报告.md)

### DAY10 — XML 数据导入功能 + XXE 攻防

在已有功能基础上，新增了 **XML 数据导入**功能。新功能为教学目的通过自定义正则提取 + 本地文件读取的方式模拟了 XML 外部实体（XXE）处理流程，引入了任意文件读取漏洞，随后进行了专项 XXE 漏洞检测与修复。

#### 新增功能

- **XML 数据导入** (`/xml-import`) — 登录用户可提交包含用户数据的 XML 文件，系统解析 `<user>` 节点并返回解析结果

#### XXE 漏洞检测

对 `/xml-import` 接口进行了 XXE、信息泄露和实体展开专项测试，发现 **3 个安全漏洞**：

| 漏洞 | CWE | CVSS 3.1 | 成因 | 攻击方式 | 危害 |
|------|-----|---------|------|----------|------|
| XXE-1 | CWE-611 | 6.5 MEDIUM | 自定义 regex + `open()` 手动处理 SYSTEM 实体 | `<!ENTITY xxe SYSTEM "C:/Windows/win.ini">` + `&xxe;` | 读取服务器任意文件（系统配置、源码、数据库） |
| XXE-2 | CWE-209 | 4.3 MEDIUM | 文件读取失败时错误消息包含完整路径 | 探测不存在的文件路径 | 泄露操作系统类型和目录结构 |
| XXE-3 | CWE-776 | 5.3 MEDIUM | 无实体数量和文件大小限制 | 大量实体定义或超大文件读取 | 服务器资源耗尽（OOM/DoS） |

#### XXE 修复

实施四层纵深防御：认证守卫 → CSRF Token 校验 → `defusedxml` 安全解析（自动禁用外部实体/DTD/实体展开） → 通用化异常处理（不泄露路径信息）。

> 📄 详细内容见 [DAY10-XXE漏洞测试与修复报告.md](DAY10-XXE漏洞测试与修复报告.md)

---

## ✨ 当前功能特性

- **用户登录认证** — Session 机制 + bcrypt 密码哈希验证
- **用户注册** — SQLite 持久化存储 + 参数化查询防注入
- **用户搜索** — 按用户名/邮箱模糊搜索，结果显示在首页
- **头像上传** — 登录用户可上传头像图片，支持预览和链接访问
- **个人中心** — 查看用户资料（ID/用户名/邮箱/手机/余额），仅本人或管理员可查看
- **余额充值** — 服务端校验金额，CSRF 保护，防止客户端篡改
- **管理面板** — 仅 admin 角色可访问，列出所有用户
- **动态页面加载** — 白名单控制的页面系统，支持 `/page?name=help` 加载帮助中心
- **帮助中心** — 常见问题与联系方式，首页一键直达
- **密码修改** — 登录后修改密码，CSRF 保护，确认密码校验
- **URL 抓取** — 登录后抓取外部 URL，6 层 SSRF 防护（协议+IP+DNS）
- **Ping 网络诊断** — 登录后执行 ping 连通性测试，终端风格显示，4 层命令注入防护
- **XML 数据导入** — 登录后提交 XML 文件导入用户数据，defusedxml 安全解析防 XXE
- **用户仪表盘** — 登录后展示个人信息（已脱敏处理）
- **安全退出** — POST + CSRF Token 双重验证
- **速率限制** — 5 次 / 5 分钟，防暴力破解
- **安全响应头** — CSP、X-Frame-Options 等全量配置
- **操作审计日志** — 登录/退出/攻击行为全程记录

## 🛡️ 安全机制

| 防护维度 | 实现方案 |
|----------|----------|
| **密码存储** | Werkzeug bcrypt 加盐哈希，永不存储明文 |
| **密钥管理** | 环境变量注入 + 密码学随机回退 (`secrets.token_hex`) |
| **CSRF 防护** | Session Token + 恒定时间比较 (`secrets.compare_digest`)，覆盖全部敏感 POST 路由 |
| **SQL 注入防护** | `?` 占位符参数化查询，SQL 逻辑与数据分离 |
| **文件上传安全** | `secure_filename()` 防路径穿越 + 后缀白名单 + UUID 唯一文件名 |
| **SSRF 防护** | 六层防御：URL 解析 + 协议白名单 + 主机名黑名单 + DNS 解析 + IP 过滤 (loopback/private/link-local) |
| **命令注入防护** | 四层防御：认证守卫 + CSRF Token + 输入白名单+元字符黑名单 + `shell=False` 参数列表执行 |
| **XXE 防护** | 四层防御：认证守卫 + CSRF Token + defusedxml 安全解析（禁用外部实体/DTD/实体展开） + 通用化异常处理 |
| **路径遍历防护** | 页面白名单 + `secure_filename()` + `realpath()` 目录 confinement 三层防御 |
| **访问控制** | IDOR 防护（session user_id 验证）+ RBAC 角色校验（admin/user）+ 认证守卫 |
| **输入校验** | 用户名白名单 `[a-zA-Z0-9_-]` + 金额范围校验 + 类型校验 |
| **会话安全** | 登录重生、30 分钟超时、HttpOnly / SameSite=Lax / Secure |
| **暴力破解** | IP 级别频率限制，5 次 / 5 分钟滑动窗口 |
| **信息泄露** | 前后端双重防护，不传输/不渲染敏感字段 |
| **安全响应头** | `X-Frame-Options: DENY`、`CSP`、`X-Content-Type-Options: nosniff` 等 |
| **调试保护** | Debug 模式默认关闭，仅绑定 127.0.0.1 |

## 🚀 快速开始

### 环境要求

- Python 3.10+
- pip

### 安装运行

```bash
# 1. 克隆项目
git clone https://github.com/0KYU/flask-u0k.git
cd flask-u0k

# 2. 安装依赖
pip install -r requirements.txt

# 3. 设置密钥（生产环境必须）
# Windows PowerShell:
$env:FLASK_SECRET_KEY = "your-secret-key-here"
# Linux / macOS:
export FLASK_SECRET_KEY="your-secret-key-here"

# 4. 启动服务（首次启动自动创建 data/users.db）
python app.py
```

访问 **http://127.0.0.1:5000** 即可使用。

### 测试账号

| 用户名 | 密码 | 角色 | ID | 余额 |
|--------|------|------|----|------|
| `admin` | `admin123` | 管理员 | 1 | 99999 |
| `alice` | `alice2025` | 普通用户 | 2 | 100 |

> 注册功能创建的用户存储在 SQLite 数据库中，默认余额为 0。登录认证目前使用内存字典，两者数据源暂未统一。

## ⚙️ 环境变量

| 变量 | 用途 | 默认值 |
|------|------|--------|
| `FLASK_SECRET_KEY` | Session 签名密钥 | 自动生成 (每次重启变化) |
| `FLASK_DEBUG` | Debug 模式 | `false` |
| `FLASK_HOST` | 绑定地址 | `127.0.0.1` |
| `FLASK_PORT` | 监听端口 | `5000` |
| `FLASK_HTTPS` | Cookie Secure 标志 | `true` (本地 HTTP 设为 `false`) |

## 📁 项目结构

```
flask-u0k/
├── app.py                                    # 主应用 (全部路由)
├── requirements.txt                          # Python 依赖
├── README.md                                 # 项目说明
├── DAY2-安全漏洞测试与修复报告.md                # DAY2 安全审计与修复报告（16 项漏洞）
├── DAY3-SQL注入漏洞测试与修复报告.md              # DAY3 SQL注入攻防报告
├── DAY4-文件上传漏洞测试与修复报告.md              # DAY4 文件上传攻防报告
├── DAY5-业务逻辑与越权漏洞的测试与修复报告.md       # DAY5 越权漏洞攻防报告
├── DAY6-文件包含漏洞测试与修复报告.md              # DAY6 文件包含漏洞攻防报告
├── DAY7-CSRF漏洞测试与修复报告.md                 # DAY7 CSRF漏洞攻防报告
├── DAY8-SSRF漏洞测试与修复报告.md                 # DAY8 SSRF漏洞攻防报告
├── DAY9-命令注入漏洞测试与修复报告.md                # DAY9 命令注入攻防报告
├── DAY10-XXE漏洞测试与修复报告.md                     # DAY10 XXE漏洞攻防报告
├── pages/
│   └── help.html                              # 帮助中心页面
├── data/
│   └── users.db                              # SQLite 用户数据库
├── templates/
│   ├── base.html                             # 基础布局 + 导航栏
│   ├── login.html                            # 登录页 (含 CSRF Token)
│   ├── register.html                         # 注册页
│   ├── upload.html                           # 头像上传页
│   ├── profile.html                          # 个人中心 (含充值、修改密码表单)
│   ├── admin.html                            # 管理面板 (admin 专属)
│   ├── ping.html                             # Ping 网络诊断 (含 CSRF Token)
│   ├── xml_import.html                       # XML 数据导入 (含 CSRF Token)
│   └── index.html                            # 仪表盘 + 搜索 + URL抓取 (已脱敏)
└── static/
    ├── css/
    │   └── style.css                         # 样式表
    └── uploads/                              # 用户上传目录
```

## 📝 技术栈

- **Web 框架**: Flask 3.x
- **密码哈希**: Werkzeug Security (bcrypt)
- **数据库**: SQLite3 (Python 标准库)
- **会话管理**: Flask Session (服务端签名 Cookie)
- **文件上传**: Werkzeug `secure_filename()` + UUID 唯一命名
- **Python 标准库**: `sqlite3`、`secrets`、`logging`、`datetime`、`collections`、`uuid`、`xml.etree.ElementTree`
- **安全库**: `defusedxml 0.7+`（XML 安全解析，防 XXE 攻击）

无第三方安全依赖，全部基于 Flask 内置功能和 Python 标准库实现。

## ⚠️ 部署建议

1. **生产环境必须设置 `FLASK_SECRET_KEY`**
2. 使用 **Gunicorn / Waitress** 替代 Flask 内置服务器
3. 启用 **HTTPS** + Nginx 反向代理
4. 将内存用户字典与 SQLite 登录**统一**为同一数据源
5. 将内存速率限制替换为 **Redis**
6. SQLite 数据库密码建议使用 **bcrypt 哈希**存储
7. 生产环境中为所有敏感路由添加**完整的审计日志**

## 📄 开源协议

MIT License
