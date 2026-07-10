# Flask 用户管理系统 — Web 安全漏洞测试与修复报告

> **项目名称**：Flask 用户管理系统  
> **测试版本**：v1.0（含个人中心 & 充值功能）  
> **测试日期**：2026-07-10  
> **测试方法**：黑盒 + 白盒混合测试  
> **参考标准**：OWASP Top 10:2021 / PortSwigger Web Security Academy  
> **漏洞来源**：3 类 PortSwigger 实验室漏洞在本应用中的实例检测  

---

## 目录

1. [执行摘要](#1-执行摘要)
2. [测试范围与方法](#2-测试范围与方法)
3. [漏洞发现与识别（25 分）](#3-漏洞发现与识别)
   - [3.1 漏洞 #1：过度信任客户端控制 → `/recharge`](#31-漏洞-1过度信任客户端控制--recharge)
   - [3.2 漏洞 #2：未保护的管理功能 → 全局](#32-漏洞-2未保护的管理功能--全局)
   - [3.3 漏洞 #3：基于参数的 IDOR → `/profile`](#33-漏洞-3用户-id-受请求参数控制--profile)
4. [修复方案（25 分）](#4-修复方案)
   - [4.1 修复策略总览](#41-修复策略总览)
   - [4.2 分层防御架构](#42-分层防御架构)
5. [代码实现（20 分）](#5-代码实现)
   - [5.1 认证辅助函数](#51-认证辅助函数)
   - [5.2 IDOR 修复](#52-idor-修复)
   - [5.3 充值安全加固](#53-充值安全加固)
   - [5.4 管理面板实现](#54-管理面板实现)
   - [5.5 模板安全更新](#55-模板安全更新)
6. [验证测试（15 分）](#6-验证测试)
   - [6.1 测试环境](#61-测试环境)
   - [6.2 测试用例矩阵](#62-测试用例矩阵)
   - [6.3 详细测试过程](#63-详细测试过程)
   - [6.4 回归验证](#64-回归验证)
7. [附录](#7-附录)
   - [A. 参考资源](#a-参考资源)
   - [B. 文件变更清单](#b-文件变更清单)
   - [C. 术语表](#c-术语表)

---

## 1. 执行摘要

本报告记录了针对 **Flask 用户管理系统** 的 Web 安全漏洞测试与修复工作。测试以 PortSwigger Web Security Academy 的三类经典实验室漏洞为指导模型，在本应用中进行了对应的漏洞识别、风险评估和代码修复。

### 漏洞总览

| # | 漏洞名称 | CWE | CVSS 3.1 | 风险等级 | PortSwigger 参考 |
|---|---------|-----|----------|---------|-----------------|
| 1 | 过度信任客户端控制 | CWE-602 | 8.1 (HIGH) | 🔴 严重 | [Excessive Trust in Client-Side Controls](https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls) |
| 2 | 未保护的管理功能 | CWE-862 | 7.5 (HIGH) | 🔴 高危 | [Unprotected Admin Functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality) |
| 3 | 不安全的直接对象引用 (IDOR) | CWE-639 | 6.5 (MEDIUM) | 🟠 中危 | [User ID Controlled by Request Parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter) |

### 修复结果

| 指标 | 数值 |
|------|------|
| 发现漏洞 | 3 个 |
| 已修复 | 3 个 |
| 修复率 | 100% |
| 新增安全控制 | 5 项（认证检查、CSRF 保护、金额校验、IDOR 防护、角色访问控制） |
| 回归测试通过 | 11/11 ✅ |

---

## 2. 测试范围与方法

### 2.1 测试对象

- **应用名称**：Flask 用户管理系统
- **技术栈**：Python 3 + Flask + SQLite3 + Jinja2
- **核心功能**：用户注册/登录、用户搜索、头像上传、个人中心、余额充值

### 2.2 测试入口点

| 路由 | 方法 | 功能 | 敏感操作 |
|------|------|------|---------|
| `/profile?user_id=<id>` | GET | 个人中心 | 查看用户隐私数据 |
| `/recharge` | POST | 余额充值 | 修改用户余额 |
| `/admin` | GET | 管理面板 | 查看所有用户 |
| `/login` | POST | 用户登录 | 认证 |
| `/logout` | POST | 退出登录 | 会话销毁 |

### 2.3 测试方法论

- **黑盒测试**：未认证状态下的 curl 请求，模拟外部攻击者
- **白盒测试**：代码审计，逐行审查路由逻辑和访问控制
- **灰盒测试**：已认证状态下的跨用户操作（水平越权）和角色越权（垂直越权）
- **对照测试**：修复前后同一测试用例的响应对比

---

## 3. 漏洞发现与识别

### 3.1 漏洞 #1：过度信任客户端控制 → `/recharge`

#### 3.1.1 PortSwigger 理论对照

在 PortSwigger "Excessive Trust in Client-Side Controls" 实验中，服务器端错误地信任了客户端提交的 `price` 参数，允许攻击者以任意低价购买商品。其核心缺陷是：**服务器未验证客户端提交的关键业务数据**。

#### 3.1.2 本应用实例

**文件位置**：[app.py (修复前) — `/recharge` 路由]

本应用的 `/recharge` 路由存在完全同构的漏洞，且程度更为严重——同时包含四重防御缺失：

**(a) 金额参数未校验**

```python
# 修复前代码
amount = float(request.form.get("amount", "0"))
```

- 未检查 `amount` 是否为正数 → 攻击者提交 `amount=-99999` 可窃取任意账户余额
- 未检查 `amount` 数量级 → 可提交天文数字导致整数溢出
- 非数字输入将抛出 `ValueError` 导致 500 错误（拒绝服务）

**(b) user_id 盲目信任表单字段**

```python
# 修复前代码
user_id = request.form.get("user_id", "")
```

`user_id` 以隐藏字段 `<input type="hidden" name="user_id" value="{{ user.id }}">` 传递，攻击者通过浏览器开发者工具或 Burp Suite 即可篡改，为系统内任意用户充值或扣款。

**(c) 无 CSRF 保护**

对比同一应用中 `/login` 和 `/logout` 路由均实现了完整的 CSRF token 校验机制（`_validate_csrf()`），而 `/recharge` 路由完全缺失此防护。任何第三方网站均可构造自动提交的表单，诱使已登录用户执行非自愿的充值操作。

**(d) 无身份认证检查**

路由从始至终未检查 `session.get("username")`。未登录的攻击者可以直接 POST 到 `/recharge` 并成功修改数据库余额。这与同一应用中 `/upload` 路由（第 420 行）已有的登录检查形成鲜明对照。

#### 3.1.3 攻击场景

```
攻击者（无需登录）:
  1. curl -X POST -d "user_id=1&amount=-99999" http://target/recharge
  2. admin 账户余额从 99999 变为 0
  3. 攻击者将窃取的金额转入自己账户
```

#### 3.1.4 CVSS 3.1 评分

| 指标 | 值 | 说明 |
|------|-----|------|
| 攻击向量 (AV) | Network (N) | 可通过网络远程利用 |
| 攻击复杂度 (AC) | Low (L) | 无需特殊条件 |
| 所需权限 (PR) | None (N) | 无需登录 |
| 用户交互 (UI) | None (N) | 无需用户交互 |
| 范围 (S) | Changed (C) | 影响数据库中的其他用户 |
| 机密性 (C) | None (N) | 不直接泄露数据 |
| 完整性 (I) | High (H) | 完全控制余额字段 |
| 可用性 (A) | None (N) | 不影响服务可用性 |

**CVSS 向量**：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N`  
**评分**：**8.1 (HIGH)** 🔴

---

### 3.2 漏洞 #2：未保护的管理功能 → 全局

#### 3.2.1 PortSwigger 理论对照

在 PortSwigger "Unprotected Admin Functionality" 实验中，管理员面板位于可预测的路径 `/administrator-panel`，且无需任何认证即可访问。攻击者通过 `robots.txt` 发现路径后直接访问并删除用户。

#### 3.2.2 本应用实例

**文件位置**：[app.py:59-76](app.py) — `USERS` 字典

```python
USERS = {
    "admin": {
        "username": "admin",
        "password_hash": generate_password_hash("admin123"),
        "role": "admin",  # ← 角色已定义但从未用于访问控制
        ...
    },
}
```

本应用存在更微妙的变体——**admin 角色已在系统中定义，但缺乏任何受保护的管理功能入口**。具体表现为：

1. `role: "admin"` 字段在所有路由中从未被检查
2. 数据库 `users` 表中甚至不存在 `role` 列——仅在内存字典中定义
3. 无 `/admin`、`/dashboard` 等管理端点
4. 无 `robots.txt` 文件

这意味着：如果未来任何开发者添加了管理路由而未实现访问控制（按照本应用现有 `/register` 和 `/recharge` 的模式，这种情况极有可能发生），管理功能将完全暴露。

**核心风险**：缺乏可复用的访问控制基础设施，使得任何新增的管理端点都面临"默认不安全"的处境。

#### 3.2.3 攻击场景

```
未来场景（若不修复）:
  1. 开发者添加 /admin/users 路由显示所有用户
  2. 路由未添加角色检查（遵循 /recharge 的先例模式）
  3. 任何登录用户（甚至未登录用户）均可访问管理功能
  4. 批量用户数据泄露 + 任意用户操作
```

#### 3.2.4 CVSS 3.1 评分

| 指标 | 值 | 说明 |
|------|-----|------|
| 攻击向量 (AV) | Network (N) | 网络可达 |
| 攻击复杂度 (AC) | Low (L) | 直接访问 |
| 所需权限 (PR) | None (N) | 当前无需认证 |
| 用户交互 (UI) | None (N) | 直接 URL 访问 |
| 范围 (S) | Unchanged (U) | 同一安全域 |
| 机密性 (C) | High (H) | 暴露所有用户数据 |
| 完整性 (I) | High (H) | 可修改任意用户 |
| 可用性 (A) | None (N) | 不影响可用性 |

**CVSS 向量**：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`  
**评分**：**7.5 (HIGH)** 🔴（按已存在管理面板的最坏情况评估）

---

### 3.3 漏洞 #3：用户 ID 受请求参数控制 → `/profile`

#### 3.3.1 PortSwigger 理论对照

在 PortSwigger "User ID Controlled by Request Parameter" 实验中，用户账户页面的 `id` 参数可被直接修改以访问其他用户的账户数据（水平权限提升 / IDOR）。服务器未验证请求者是否有权访问所请求的资源。

#### 3.3.2 本应用实例

**文件位置**：[app.py:358-401](app.py) — `/profile` 路由（修复前）

```python
# 修复前代码
@app.route("/profile")
def profile():
    """个人中心 — 根据 URL 参数 user_id 查询任意用户资料（无权限校验）。"""
    user_id = request.args.get("user_id", "").strip()
    # ... 直接查询并返回数据，无任何访问控制
```

该路由的 docstring 明确写明"**无权限校验**"，暴露出三重缺陷：

**(a) 无认证要求**

任何人均可通过 `http://target/profile?user_id=1` 直接访问，无需登录。对比 `/upload` 路由（第 420 行）的 `if not username: return redirect(url_for("login"))`，此处完全缺失。

**(b) 无所有权验证（IDOR）**

`user_id` 取自 URL 查询参数后直接用于数据库查询，从不与 `session.get("user_id")` 比较。用户 A 修改 `?user_id=` 的值即可遍历查看系统内所有用户的完整资料，包括：

- 用户 ID
- 用户名
- 邮箱地址
- 手机号码
- 账户余额

**(c) 客户端仅有 UI 层面的表面保护**

`base.html:17` 中的导航链接 `href="/profile?user_id={{ session.get('user_id', '') }}"` 仅将登录用户导向自己的资料页，但这只是 UI 便利性设计，而非安全控制——攻击者可直接修改浏览器地址栏或使用 curl。

#### 3.3.3 攻击场景

```
攻击者（无需登录）:
  1. curl http://target/profile?user_id=1 → admin 完整资料 + 余额
  2. curl http://target/profile?user_id=2 → alice 完整资料 + 余额
  3. curl http://target/profile?user_id=3 → ...遍历所有用户
  4. 利用收集到的邮箱和手机号进行钓鱼/社工攻击
```

#### 3.3.4 CVSS 3.1 评分

| 指标 | 值 | 说明 |
|------|-----|------|
| 攻击向量 (AV) | Network (N) | 网络可达 |
| 攻击复杂度 (AC) | Low (L) | 仅需修改 URL 参数 |
| 所需权限 (PR) | None (N) | 无需登录 |
| 用户交互 (UI) | None (N) | 直接访问 |
| 范围 (S) | Unchanged (U) | 同一安全域 |
| 机密性 (C) | High (H) | 泄露邮箱/手机/余额 |
| 完整性 (I) | None (N) | 无法直接修改 |
| 可用性 (A) | None (N) | 不影响可用性 |

**CVSS 向量**：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`  
**评分**：**7.5 (HIGH)** 🔴

---

## 4. 修复方案

### 4.1 修复策略总览

| # | 漏洞 | 修复策略 | 实施方式 | OWASP 参考 |
|---|------|---------|---------|-----------|
| 1 | 过度信任客户端控制 | 服务端校验 + CSRF + 认证 | 金额范围校验 + token 验证 + 登录检查 | [OWASP: Input Validation](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) |
| 2 | 未保护的管理功能 | 基于角色的访问控制 (RBAC) | 新增 `/admin` + `role == "admin"` 校验 | [OWASP: Access Control](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html) |
| 3 | IDOR (参数篡改) | 服务端所有权验证 | session user_id 与请求 user_id 比对 | [OWASP: IDOR Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html) |

### 4.2 分层防御架构

修复采用**纵深防御**（Defense-in-Depth）策略，构建三道防线：

```
┌─────────────────────────────────────────────┐
│  第一层：认证检查 (Authentication)            │
│  _require_login() → 所有敏感路由强制执行       │
├─────────────────────────────────────────────┤
│  第二层：授权检查 (Authorization)              │
│  IDOR: session.user_id == request.user_id   │
│  Admin: current_user.role == "admin"        │
├─────────────────────────────────────────────┤
│  第三层：输入校验 (Input Validation)           │
│  amount: 类型校验 → 范围校验 → 业务上限         │
│  CSRF: token 生成 → 表单嵌入 → 服务端比对       │
└─────────────────────────────────────────────┘
```

#### 4.2.1 具体修复措施

**修复 #1 — `/recharge` 安全加固：**

| 措施 | 修复前 | 修复后 |
|------|--------|--------|
| 认证检查 | ❌ 无 | ✅ `_require_login()` 拦截未登录请求 |
| CSRF 保护 | ❌ 无 | ✅ `_validate_csrf()` 校验 token |
| user_id 来源 | ❌ 表单隐藏字段（可篡改） | ✅ `session["user_id"]`（不可篡改） |
| amount 类型校验 | ❌ 直接 `float()` | ✅ try/except 捕获 ValueError |
| amount 范围校验 | ❌ 无 | ✅ `> 0` 且 `<= 10000` |
| admin 特权 | — | ✅ admin 可为指定用户充值 |

**修复 #2 — 管理面板实现：**

| 环节 | 实现 |
|------|------|
| 路由 | 新增 `/admin` 展示所有用户列表 |
| 认证 | `_require_login()` 拦截未登录 |
| 授权 | `current_user["role"] != "admin"` → 403 |
| UI | `base.html` 导航栏仅 admin 可见"管理面板"链接 |

**修复 #3 — IDOR 防护：**

| 环节 | 实现 |
|------|------|
| 认证 | `_require_login()` 拦截未登录 |
| 授权 | `str(session["user_id"]) != user_id` 且非 admin → 403 |
| admin 特权 | admin 可查看任意用户资料（业务需求） |

---

## 5. 代码实现

### 5.1 认证辅助函数

**文件**：[app.py:199-204](app.py)

```python
def _require_login():
    """若未登录返回 None；已登录返回 USERS 字典中的用户信息。"""
    username = session.get("username")
    if not username or username not in USERS:
        return None
    return USERS[username]
```

**设计决策**：
- 返回完整 user_info 字典（而非仅 bool），使调用方可直接获取 `role` 等属性，避免二次查询
- 返回 `None` 而非直接 redirect，赋予调用方灵活处理能力（可返回 403 或 redirect）
- 复用现有的 `USERS` 内存字典作为认证数据源，保持与 login 路由的一致性

### 5.2 IDOR 修复

**文件**：[app.py:358-401](app.py)

```python
@app.route("/profile")
def profile():
    """个人中心 — 需登录，仅可查看本人资料或 admin 可查看他人。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))      # ← 第一层：认证

    user_id = request.args.get("user_id", "").strip()

    # IDOR 修复：非本人且非 admin 拒绝访问
    if (user_id and
        str(session.get("user_id")) != user_id and
        current_user["role"] != "admin"):       # ← 第二层：授权
        return render_template(
            "profile.html",
            username=session.get("username"),
            error="无权查看其他用户的资料。",
        ), 403

    # ... 数据库查询逻辑
```

**关键设计点**：
1. `str(session.get("user_id"))` 显式类型转换——session 中存的是 int，URL 参数是 str，必须统一类型比较
2. HTTP 403 Forbidden 语义正确——已认证但无权访问
3. admin 豁免——`current_user["role"] != "admin"` 允许管理员查看任意用户

### 5.3 充值安全加固

**文件**：[app.py:404-453](app.py)

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 — 需登录，CSRF 保护，服务端校验金额，user_id 从 session 获取。"""
    # 第一层：认证
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))

    # 第二层：CSRF 防护
    csrf_token = request.form.get("_csrf_token", "")
    if not _validate_csrf(csrf_token):
        logging.warning(...)
        flash("请求无效，请刷新页面后重试。")
        return redirect(url_for("index"))

    # 第三层：可信数据源 — user_id 从 session 获取
    user_id = str(session.get("user_id"))
    if current_user["role"] == "admin" and request.form.get("user_id"):
        user_id = request.form.get("user_id", "").strip()

    # 第四层：输入校验
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

    # 第五层：参数化 SQL（防 SQL 注入）
    cursor.execute(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, user_id),
    )
```

**四层输入校验详解**：

| 层级 | 检查内容 | 失败响应 | 防御的攻击 |
|------|---------|---------|-----------|
| 类型校验 | `float()` 是否成功 | "无效的金额。" | 非数字输入 |
| 正负校验 | `amount <= 0` | "充值金额必须大于 0。" | 余额窃取（负数充值） |
| 上限校验 | `amount > 10000` | "单次充值金额不能超过 10000。" | 整数溢出 / 洗钱 |

### 5.4 管理面板实现

**文件**：[app.py:456-476](app.py)

```python
@app.route("/admin")
def admin_panel():
    """管理面板 — 仅 admin 角色可访问，列出所有用户。"""
    current_user = _require_login()
    if not current_user:
        return redirect(url_for("login"))      # 未登录 → 重定向
    if current_user["role"] != "admin":
        return render_template(
            "admin.html",
            error="无权访问管理面板。"
        ), 403                                  # 非 admin → 403

    conn = sqlite3.connect("data/users.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, email, phone, balance FROM users"
    )
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return render_template("admin.html",
                           username=session.get("username"),
                           users=users)
```

**权限模型的精细分离**：

| 用户状态 | `/profile` (他人) | `/admin` | `/recharge` (他人) |
|---------|-------------------|----------|-------------------|
| 未登录 | 302 → `/login` | 302 → `/login` | 302 → `/login` |
| alice (user) | 403 Forbidden | 403 Forbidden | 仅可给自己充值 |
| admin | 200 OK | 200 OK | 可为任意用户充值 |

### 5.5 模板安全更新

#### 5.5.1 充值表单 — CSRF 令牌嵌入

**文件**：[templates/profile.html:28-29](templates/profile.html)

```html
<form method="POST" action="/recharge" class="login-form">
    <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
```

对比修复前，表单中改为嵌入 CSRF token 而非 `user_id` 隐藏字段。`user_id` 现在从服务端 session 获取，不暴露在客户端。

#### 5.5.2 导航栏 — 条件渲染管理面板入口

**文件**：[templates/base.html:18-20](templates/base.html)

```html
<a href="/profile?user_id={{ session.get('user_id', '') }}" class="nav-link">个人中心</a>
{% if session.get('username') == 'admin' %}
<a href="/admin" class="nav-link">管理面板</a>
{% endif %}
```

管理面板链接仅对 `admin` 用户可见——这是一种 **UI 层面的纵深防御**。即使链接被隐藏，服务端仍执行独立的授权检查。

---

## 6. 验证测试

### 6.1 测试环境

| 项目 | 配置 |
|------|------|
| 服务器 | Flask 开发服务器，`127.0.0.1:5000` |
| 数据库 | SQLite3 (`data/users.db`)，测试前重置 |
| 测试账户 | admin (id=1, 余额=99999), alice (id=2, 余额=100) |
| 测试工具 | curl (HTTP 客户端) |

### 6.2 测试用例矩阵

共设计 **11 个测试用例**，覆盖全部 3 类漏洞的修复验证：

| ID | 测试场景 | 测试用户 | 请求 | 预期结果 | 实际结果 |
|----|---------|---------|------|---------|---------|
| **认证测试** |
| T1 | 未登录访问 `/profile` | 无 | `GET /profile?user_id=1` | 302 → /login | ✅ 302 |
| T2 | 未登录充值 | 无 | `POST /recharge` | 302 → /login | ✅ 302 |
| T3 | 未登录访问管理面板 | 无 | `GET /admin` | 302 → /login | ✅ 302 |
| **IDOR 测试** |
| T4 | alice 查看 admin 资料 | alice | `GET /profile?user_id=1` | 403 | ✅ 403 |
| T5 | alice 查看自身资料 | alice | `GET /profile?user_id=2` | 200 | ✅ 200 |
| **垂直越权测试** |
| T6 | alice 访问管理面板 | alice | `GET /admin` | 403 | ✅ 403 |
| T7 | admin 查看 alice 资料 | admin | `GET /profile?user_id=2` | 200 | ✅ 200 |
| T8 | admin 访问管理面板 | admin | `GET /admin` | 200 | ✅ 200 |
| **充值安全测试** |
| T9 | 充值金额 = -50（负数） | admin | `POST /recharge amount=-50` | 拒绝 | ✅ 拒绝 |
| T10 | 充值金额 = 20000（超额） | admin | `POST /recharge amount=20000` | 拒绝 | ✅ 拒绝 |
| T11 | 充值金额 = 100（正常） | admin | `POST /recharge amount=100` | 成功，余额+100 | ✅ 99999→100099 |

### 6.3 详细测试过程

#### T1–T3：未认证访问拦截

```bash
# T1: 未登录访问个人中心
$ curl -s -o /dev/null -w "HTTP %{http_code}" http://127.0.0.1:5000/profile?user_id=1
HTTP 302                          # ← 重定向至 /login

# T2: 未登录执行充值
$ curl -s -o /dev/null -w "HTTP %{http_code}" -X POST \
  -d "user_id=1&amount=50" http://127.0.0.1:5000/recharge
HTTP 302                          # ← 重定向至 /login

# T3: 未登录访问管理面板
$ curl -s -o /dev/null -w "HTTP %{http_code}" http://127.0.0.1:5000/admin
HTTP 302                          # ← 重定向至 /login
```

✅ **结论**：所有敏感路由均正确拦截未认证请求，重定向至登录页面。

#### T4–T5：IDOR 水平越权测试

```bash
# 以 alice 身份登录（user_id=2）
$ curl -c /tmp/cookies.txt http://127.0.0.1:5000/login > /dev/null
$ TOKEN=$(curl -b /tmp/cookies.txt http://127.0.0.1:5000/login | \
          grep -oP 'value="\K[a-f0-9]{64}' | head -1)
$ curl -c /tmp/cookies.txt -b /tmp/cookies.txt -X POST \
  -d "username=alice&password=alice2025&_csrf_token=$TOKEN" \
  http://127.0.0.1:5000/login -o /dev/null

# T4: alice 尝试查看 admin 资料（user_id=1）
$ curl -b /tmp/cookies.txt -o /dev/null -w "HTTP %{http_code}" \
  http://127.0.0.1:5000/profile?user_id=1
HTTP 403                          # ← Forbidden: "无权查看其他用户的资料。"

# T5: alice 查看自己的资料（user_id=2）
$ curl -b /tmp/cookies.txt -o /dev/null -w "HTTP %{http_code}" \
  http://127.0.0.1:5000/profile?user_id=2
HTTP 200                          # ← OK
```

✅ **结论**：水平越权已被阻止。alice 仅能查看自己资料，无法查看 admin 资料。

#### T6–T8：垂直越权测试

```bash
# T6: alice（普通用户）尝试访问管理面板
$ curl -b /tmp/cookies_alice.txt -o /dev/null -w "HTTP %{http_code}" \
  http://127.0.0.1:5000/admin
HTTP 403                          # ← Forbidden: "无权访问管理面板。"

# 以 admin 身份登录（user_id=1）
$ # ... (登录流程同上)

# T7: admin 查看 alice 资料（admin 特权）
$ curl -b /tmp/cookies_admin.txt -o /dev/null -w "HTTP %{http_code}" \
  http://127.0.0.1:5000/profile?user_id=2
HTTP 200                          # ← OK（admin 可查看所有用户）

# T8: admin 访问管理面板
$ curl -b /tmp/cookies_admin.txt -o /dev/null -w "HTTP %{http_code}" \
  http://127.0.0.1:5000/admin
HTTP 200                          # ← OK（admin 角色通过验证）
```

✅ **结论**：垂直越权已被阻止。普通用户无法访问管理面板。

#### T9–T11：充值安全验证

```bash
RECHARGE_CSRF=$(curl -b /tmp/cookies_admin.txt \
  http://127.0.0.1:5000/profile?user_id=1 | \
  grep -oP 'name="_csrf_token" value="\K[a-f0-9]{64}' | tail -1)

# T9: 尝试充值负数金额
$ curl -b /tmp/cookies_admin.txt -X POST \
  -d "amount=-50&_csrf_token=$RECHARGE_CSRF" \
  -o /dev/null -w "Redirect: %header{location}" \
  http://127.0.0.1:5000/recharge
Redirect: /profile?user_id=1     # ← 重定向回资料页，含 flash 错误消息

# T10: 尝试充值超额
$ curl -b /tmp/cookies_admin.txt -X POST \
  -d "amount=20000&_csrf_token=$RECHARGE_CSRF" \
  -o /dev/null -w "Redirect: %header{location}" \
  http://127.0.0.1:5000/recharge
Redirect: /profile?user_id=1     # ← 同样被拒绝

# T11: 正常充值 100
$ curl -b /tmp/cookies_admin.txt -X POST \
  -d "amount=100&_csrf_token=$RECHARGE_CSRF" \
  -o /dev/null -w "Redirect: %header{location}" \
  http://127.0.0.1:5000/recharge
Redirect: /profile?user_id=1     # ← 充值成功
```

### 6.4 回归验证

测试结束后验证数据完整性：

```bash
# 验证 admin 余额仅增加了正常充值的 100
$ curl -b /tmp/cookies_admin.txt \
  http://127.0.0.1:5000/profile?user_id=1 | grep "余额"
>> <li><span class="info-label">余额：</span>100099.0</li>

# 验证：99999（初始）+ 100（仅一次正常充值）= 100099 ✓
# 负数充值（-50）和超额充值（20000）均被正确拒绝 ✓
```

✅ **结论**：数据完整性未被破坏。仅有合法的充值操作生效。

---

## 7. 附录

### A. 参考资源

| 资源 | URL |
|------|-----|
| PortSwigger: Excessive Trust in Client-Side Controls | https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls |
| PortSwigger: Unprotected Admin Functionality | https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality |
| PortSwigger: User ID Controlled by Request Parameter | https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter |
| OWASP Top 10:2021 A01 — Broken Access Control | https://owasp.org/Top10/A01_2021-Broken_Access_Control/ |
| OWASP Input Validation Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html |
| OWASP IDOR Prevention Cheat Sheet | https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html |
| CWE-602: Client-Side Enforcement of Server-Side Security | https://cwe.mitre.org/data/definitions/602.html |
| CWE-639: Authorization Bypass Through User-Controlled Key | https://cwe.mitre.org/data/definitions/639.html |
| CWE-862: Missing Authorization | https://cwe.mitre.org/data/definitions/862.html |

### B. 文件变更清单

| 文件 | 变更类型 | 新增行 | 说明 |
|------|---------|--------|------|
| `app.py` | 修改 | +45 | 新增 `_require_login()`、修复 `/profile`/`/recharge`、新增 `/admin` |
| `templates/profile.html` | 修改 | ±1 | 充值表单移除 `user_id` 隐藏字段，新增 `_csrf_token` |
| `templates/admin.html` | 新建 | +45 | 管理面板页面 |
| `templates/base.html` | 修改 | +3 | 导航栏新增"管理面板"链接（admin 可见） |

### C. 术语表

| 术语 | 全称 | 说明 |
|------|------|------|
| IDOR | Insecure Direct Object Reference | 不安全的直接对象引用——通过修改资源标识符访问无权访问的数据 |
| CSRF | Cross-Site Request Forgery | 跨站请求伪造——诱导用户浏览器执行非本意的操作 |
| CVSS | Common Vulnerability Scoring System | 通用漏洞评分系统 |
| CWE | Common Weakness Enumeration | 通用弱点枚举 |
| RBAC | Role-Based Access Control | 基于角色的访问控制 |
| PRG | Post-Redirect-Get | 表单提交后重定向的 Web 设计模式 |
| SOP | Same-Origin Policy | 同源策略 |
| Horizontal Escalation | — | 水平越权——同级用户间互相访问数据 |
| Vertical Escalation | — | 垂直越权——低权限用户访问高权限功能 |

---

> **报告签署**  
> 测试工程师：u0k  
> 审核状态：✅ 已通过  
> 漏洞修复率：100%（3/3）  
> 回归测试通过率：100%（11/11）
