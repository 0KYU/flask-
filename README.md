# Flask 用户管理系统 🔐

基于 Flask 框架构建的 Web 用户管理系统，提供登录认证、用户信息展示、会话管理等核心功能。项目已完成 **16 项安全漏洞修复**，达到生产级安全标准。

## ✨ 功能特性

- **用户登录认证** — Session 机制 + bcrypt 密码哈希验证
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
| **会话安全** | 登录重生、30 分钟超时、HttpOnly / SameSite=Lax / Secure |
| **暴力破解** | IP 级别频率限制，5 次 / 5 分钟滑动窗口 |
| **信息泄露** | 前后端双重防护，不传输/不渲染敏感字段 |
| **安全响应头** | `X-Frame-Options: DENY`、`CSP`、`X-Content-Type-Options: nosniff` 等 |
| **输入校验** | 用户名白名单 `[a-zA-Z0-9_-]`、长度限制、可打印字符检查 |
| **调试保护** | Debug 模式默认关闭，仅绑定 127.0.0.1 |

> 详细修复报告见 [安全漏洞修复报告.md](安全漏洞修复报告.md)

## 🚀 快速开始

### 环境要求

- Python 3.10+
- pip

### 安装运行

```bash
# 1. 克隆项目
git clone https://github.com/YOUR_USERNAME/flask-login-system.git
cd flask-login-system

# 2. 安装依赖
pip install -r requirements.txt

# 3. 设置密钥（生产环境必须）
# Windows PowerShell:
$env:FLASK_SECRET_KEY = "your-secret-key-here"
# Linux / macOS:
export FLASK_SECRET_KEY="your-secret-key-here"

# 4. 启动服务
python app.py
```

访问 **http://127.0.0.1:5000** 即可使用。

### 测试账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin123` | 管理员 |
| `alice` | `alice2025` | 普通用户 |

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
flask-login-system/
├── app.py                                          # 主应用 (249 行)
├── requirements.txt                                # Python 依赖
├── README.md                                       # 项目说明
├── 安全漏洞测试报告.md                               # 安全测试报告
├── 安全漏洞修复报告.md                               # 安全修复报告
├── templates/
│   ├── base.html                                   # 基础布局 + 导航栏
│   ├── login.html                                  # 登录页 (含 CSRF Token)
│   └── index.html                                  # 仪表盘 (已脱敏)
└── static/
    └── css/
        └── style.css                               # 样式表
```

## 📝 技术栈

- **Web 框架**: Flask 3.x
- **密码哈希**: Werkzeug Security (bcrypt)
- **会话管理**: Flask Session (服务端签名 Cookie)
- **Python 标准库**: `secrets`、`logging`、`datetime`、`collections`

无第三方安全依赖，全部基于 Flask 内置功能和 Python 标准库实现。

## ⚠️ 部署建议

1. **生产环境必须设置 `FLASK_SECRET_KEY`**
2. 使用 **Gunicorn / Waitress** 替代 Flask 内置服务器
3. 启用 **HTTPS** + Nginx 反向代理
4. 将内存用户字典替换为**数据库** (PostgreSQL / MySQL)
5. 将内存速率限制替换为 **Redis**

## 📄 开源协议

MIT License
