# Flask 用户管理系统 🔐

基于 Flask 框架构建的 Web 用户管理系统，提供登录认证、用户注册、搜索、头像上传、个人中心、充值等核心功能。项目经历了**从漏洞百出到逐步加固**的完整安全演进过程。

## 📖 项目演进历程

### 初始版本 — 未检测的原始状态

项目最初是一个基础的 Flask 登录应用，采用最简单的实现方式，存在大量安全隐患，包括：

- 硬编码密钥、明文密码存储、无 CSRF 防护、无速率限制、无安全响应头、无输入校验等共计 **16 项安全漏洞**。

### DAY2 — 安全漏洞全面修复

对初始版本进行了完整的安全审计，逐一修复了全部 **16 项安全漏洞**：

| 严重级别 | 数量 | 典型漏洞 | 修复方案 |
|----------|------|----------|----------|
| 🔴 **严重** | 3 | 硬编码密钥、明文密码、Debug 模式外露 | 环境变量密钥 + bcrypt 哈希 + 默认关闭 Debug |
| 🟠 **高危** | 5 | 密码泄露在响应、Session 固定、CSRF 缺失等 | 前后端脱敏 + Session 重生 + CSRF Token |
| 🟡 **中危** | 3 | 无速率限制、Session 无超时、GET 登出 | IP 滑动窗口 + 30 分钟超时 + POST 登出 |
| 🟢 **低危** | 5 | 缺少安全头、输入无校验等 | CSP/X-Frame-Options + 白名单校验 |

> 📄 详细内容见 [DAY2-安全漏洞测试报告.md](DAY2-安全漏洞测试报告.md) 和 [DAY2-安全漏洞修复报告.md](DAY2-安全漏洞修复报告.md)

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

> 📄 详细内容见 [DAY5-越权漏洞测试与修复报告.md](DAY5-越权漏洞测试与修复报告.md)

---

## ✨ 当前功能特性

- **用户登录认证** — Session 机制 + bcrypt 密码哈希验证
- **用户注册** — SQLite 持久化存储 + 参数化查询防注入
- **用户搜索** — 按用户名/邮箱模糊搜索，结果显示在首页
- **头像上传** — 登录用户可上传头像图片，支持预览和链接访问
- **个人中心** — 查看用户资料（ID/用户名/邮箱/手机/余额），仅本人或管理员可查看
- **余额充值** — 服务端校验金额，CSRF 保护，防止客户端篡改
- **管理面板** — 仅 admin 角色可访问，列出所有用户
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
| **CSRF 防护** | Session Token + 恒定时间比较 (`secrets.compare_digest`) |
| **SQL 注入防护** | `?` 占位符参数化查询，SQL 逻辑与数据分离 |
| **文件上传安全** | `secure_filename()` 防路径穿越 + 后缀白名单 + UUID 唯一文件名 |
| **访问控制** | IDOR 防护（session user_id 验证）+ RBAC 角色校验（admin/user） |
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
├── DAY2-安全漏洞测试报告.md                    # DAY2 安全测试报告
├── DAY2-安全漏洞修复报告.md                    # DAY2 安全修复报告
├── DAY3-SQL注入漏洞测试与修复报告.md            # DAY3 SQL注入攻防报告
├── DAY4-文件上传漏洞测试与修复报告.md            # DAY4 文件上传攻防报告
├── DAY5-越权漏洞测试与修复报告.md               # DAY5 越权漏洞攻防报告
├── data/
│   └── users.db                              # SQLite 用户数据库
├── templates/
│   ├── base.html                             # 基础布局 + 导航栏
│   ├── login.html                            # 登录页 (含 CSRF Token)
│   ├── register.html                         # 注册页
│   ├── upload.html                           # 头像上传页
│   ├── profile.html                          # 个人中心 (含充值表单)
│   ├── admin.html                            # 管理面板 (admin 专属)
│   └── index.html                            # 仪表盘 + 搜索 (已脱敏)
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
- **Python 标准库**: `sqlite3`、`secrets`、`logging`、`datetime`、`collections`、`uuid`

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
