# Flask 用户管理系统 — DAY4 文件上传漏洞测试与修复报告

---

## 文档信息

| 项目 | 内容 |
|------|------|
| **项目名称** | Flask 用户管理系统 (flask登录) |
| **报告日期** | 2026-07-09 |
| **测试范围** | 文件上传漏洞专项检测 |
| **测试接口** | `/upload` |
| **修复文件数** | 1 个文件 (`app.py`) |
| **威胁等级** | 🔴 **严重** (Critical) |

---

## 一、漏洞总览

| 编号 | 漏洞名称 | 成因 | 严重级别 | 利用难度 |
|------|----------|------|----------|----------|
| UPL-1 | 路径穿越 (Path Traversal) | `file.filename` 直接拼接到 `os.path.join()`，未经清洗 | 🔴 严重 | ⭐ 极低 |
| UPL-2 | 任意文件类型上传 (XSS) | 无文件后缀 / MIME 类型检查，文件直接存入静态目录 | 🔴 高危 | ⭐ 极低 |
| UPL-3 | 文件覆盖 | 使用用户原始文件名保存，不生成唯一文件名 | 🟠 中危 | ⭐ 极低 |

**漏洞根因**：新增上传功能时，为教学演示目的未进行任何安全检查——不校验文件类型、不使用安全文件名、不生成唯一文件名。攻击者可上传恶意文件至任意目录，或上传 HTML 页面执行 XSS 攻击。

---

## 二、漏洞详情与攻击验证

### UPL-1 | 路径穿越 — `/upload`

**漏洞代码** (`app.py:360`)：

```python
filepath = os.path.join(upload_dir, file.filename)
file.save(filepath)
```

#### 攻击载荷 1：写入父目录

```bash
POST /upload
Content-Type: multipart/form-data

file=@payload.txt; filename=../escape_test.txt
```

**等价路径**：
```
os.path.join("static/uploads", "../escape_test.txt")
→ static/uploads/../escape_test.txt
→ static/escape_test.txt
```

**结果**：文件被写入 `static/escape_test.txt`，成功逃逸出 `uploads/` 目录。

✅ **路径穿越成功，文件写入非预期目录。**

#### 攻击载荷 2：深层逃逸 — 写入用户目录

```bash
POST /upload
Content-Type: multipart/form-data

file=@payload.txt; filename=../../../../deep_escape.txt
```

**结果**：文件被写入 `/c/Users/19100/deep_escape.txt`，完全逃逸出项目目录。

✅ **深层路径穿越成功，文件写入用户 Home 目录。**

#### 攻击载荷 3：覆盖同级文件

```bash
POST /upload
Content-Type: multipart/form-data

file=@malicious.py; filename=../app.py
```

**结果**：文件被写入 `static/app.py`。虽未覆盖项目根 `app.py`（路径仅上溯一级），但成功在 `static/` 目录中创建了同名文件。

✅ **路径穿越可覆盖同级静态文件。**

---

### UPL-2 | 任意文件类型上传 — `/upload`

**漏洞代码**：整个 `/upload` 路由中无任何文件类型校验逻辑。

#### 攻击载荷 1：HTML 文件 — XSS

```bash
POST /upload
Content-Type: multipart/form-data

file=xss_test.html  (内容: <html><body><script>alert("XSS")</script><h1>XSS_PAGE</h1></body></html>)
```

**结果**：上传成功。
**访问**：`http://127.0.0.1:5000/static/uploads/xss_test.html`

浏览器正常渲染 HTML，`<script>` 标签被执行。

✅ **HTML 文件上传成功，可执行任意 JavaScript（XSS）。**

#### 攻击载荷 2：PHP 文件

```bash
POST /upload
Content-Type: multipart/form-data

file=shell.php  (内容: <?php echo "PHP_SHELL"; ?>)
```

**结果**：上传成功。Flask 不解析 PHP（以静态文件形式返回源码），但若部署于 Apache + mod_php 环境下可能存在服务端代码执行风险。

✅ **PHP 文件上传成功，存在潜在的 WebShell 风险。**

#### 攻击载荷 3：Python 文件

```bash
POST /upload
Content-Type: multipart/form-data

file=evil.py  (内容: print("EVIL_CODE"))
```

**结果**：上传成功。Flask 以静态文件形式返回源码，未被服务端执行，但存在代码泄露风险。

✅ **任意代码文件上传成功。**

---

### UPL-3 | 文件覆盖 — `/upload`

**漏洞代码**：文件名直接使用用户输入，无唯一化处理。

#### 攻击载荷：同名文件覆盖

```bash
# 第一次上传
POST /upload
file=avatar.png  (内容: "ORIGINAL_CONTENT_V1")
→ 保存为 static/uploads/avatar.png

# 第二次上传（不同内容，同名）
POST /upload
file=avatar.png  (内容: "OVERWRITTEN_V2_MALICIOUS")
→ 覆盖 static/uploads/avatar.png
```

**结果**：文件内容从 `ORIGINAL_CONTENT_V1` 变为 `OVERWRITTEN_V2_MALICIOUS`。

✅ **同名文件覆盖成功，其他用户的头像可被替换。**

---

## 三、漏洞影响评估

| 影响维度 | 风险等级 | 说明 |
|----------|----------|------|
| **服务器文件系统** | 🔴 严重 | 攻击者可将任意文件写入服务器任意可写目录 |
| **客户端安全** | 🔴 高危 | 上传 HTML 文件可执行 XSS，窃取同源 Cookie/Session |
| **数据完整性** | 🟠 中危 | 同名文件覆盖导致已上传文件被替换 |
| **可用性** | 🟠 中危 | 攻击者可上传大量垃圾文件消耗磁盘空间（16MB/次限制） |
| **利用门槛** | 🔴 极低 | 仅需登录后使用 curl 或浏览器即可发起攻击 |

---

## 四、修复方案

### 修复原则

三层防御：

1. **文件名清洗** — 使用 Werkzeug 内置 `secure_filename()` 剥离路径穿越字符
2. **类型白名单** — 仅允许图片后缀，拒绝可执行文件类型
3. **唯一化命名** — UUID 前缀确保文件名不冲突，杜绝覆盖

### 修复点 1：导入安全工具 (`app.py:4,12-13`)

```python
# ===== 新增导入 =====
import uuid
from werkzeug.utils import secure_filename
```

### 修复点 2：允许后缀白名单 (`app.py:52`)

```python
# ===== 新增配置 =====
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
```

### 修复点 3：重写 `/upload` 路由 (`app.py:342-390`)

```python
# ===== 修复前 =====
upload_dir = os.path.join("static", "uploads")
os.makedirs(upload_dir, exist_ok=True)
filepath = os.path.join(upload_dir, file.filename)
file.save(filepath)
file_url = url_for("static", filename=f"uploads/{file.filename}")

# ===== 修复后 =====
# 1. 清洗文件名，剥离 ../ 等路径成分
filename = secure_filename(file.filename)
if filename == "":
    return render_template("upload.html", error="无效的文件名。")

# 2. 文件类型白名单
ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
if ext not in ALLOWED_EXTENSIONS:
    return render_template(
        "upload.html",
        error=f"不支持的文件类型（.{ext}），请上传图片文件（png, jpg, jpeg, gif, webp）。",
    )

# 3. UUID 前缀确保文件名唯一
unique_filename = f"{uuid.uuid4().hex}_{filename}"

upload_dir = os.path.join("static", "uploads")
os.makedirs(upload_dir, exist_ok=True)
filepath = os.path.join(upload_dir, unique_filename)
file.save(filepath)
file_url = url_for("static", filename=f"uploads/{unique_filename}")
```

### 为什么三层防御各司其职？

| 攻击 | `secure_filename()` | 后缀白名单 | UUID 前缀 |
|------|:---:|:---:|:---:|
| `../escape.txt` | ✅ 剥离为 `escape.txt` | ✅ 拒绝 `.txt` | — |
| `../../../../deep.txt` | ✅ 剥离为 `deep.txt` | ✅ 拒绝 `.txt` | — |
| `xss.html` | — | ✅ 拒绝 `.html` | — |
| `shell.php` | — | ✅ 拒绝 `.php` | — |
| 同名 `avatar.png` 覆盖 | — | — | ✅ 唯一化 |
| 正常上传 `avatar.png` | ✅ 通过 | ✅ 通过 | ✅ 通过 |

---

## 五、修复验证

### 验证环境

- **URL**: `http://127.0.0.1:5000`
- **认证状态**: 已登录 (admin)
- **验证日期**: 2026-07-09

### 验证结果

| 编号 | 测试项 | 测试 Payload | 修复前 | 修复后 |
|------|--------|-------------|:---:|:---:|
| V1 | 路径穿越（一级） | `filename=../escape.txt` | ❌ 写入 `static/escape.txt` | ✅ 拒绝 — "不支持的文件类型" |
| V2 | 路径穿越（深层） | `filename=../../../../deep.txt` | ❌ 写入用户 Home 目录 | ✅ 拒绝 — "不支持的文件类型" |
| V3 | HTML/XSS 上传 | `filename=xss.html` | ❌ 上传成功，可执行 XSS | ✅ 拒绝 — ".html 不支持" |
| V4 | PHP 上传 | `filename=shell.php` | ❌ 上传成功 | ✅ 拒绝 — ".php 不支持" |
| V5 | Python 上传 | `filename=evil.py` | ❌ 上传成功 | ✅ 拒绝 — ".py 不支持" |
| V6 | 文件覆盖 | 两次上传 `avatar.png` | ❌ 文件被覆盖 | ✅ 生成两个唯一文件名 |
| V7 | 正常 PNG 上传 | `filename=avatar.png` | ✅ 成功 | ✅ 成功 |
| V8 | 正常 JPG 上传 | `filename=photo.jpg` | ✅ 成功 | ✅ 成功 |

### V6 详细验证（文件覆盖修复）

```
第一次上传 avatar.png →
  文件: 271002a1d6ba426193979cb3cd7d72ec_avatar.png

第二次上传 avatar.png →
  文件: 5004726871814d03ab5b37050be17cb9_avatar.png
```

两个文件共存于 `static/uploads/`，互不覆盖。

### 验证结论

> ✅ **3 项文件上传漏洞全部修复成功，正常的图片上传功能不受影响。**

---

## 六、修复总结

| 维度 | 详情 |
|------|------|
| **修复漏洞数** | 3 个（UPL-1 路径穿越、UPL-2 任意文件类型、UPL-3 文件覆盖） |
| **影响接口数** | 1 个（`/upload`） |
| **修改文件数** | 1 个（`app.py`） |
| **修改行数** | 约 20 行（新增 2 行导入、3 行配置、15 行路由逻辑） |
| **修复方式** | 三层防御：`secure_filename()` + 后缀白名单 + UUID 唯一文件名 |
| **新增依赖** | 无（`uuid` 和 `secure_filename` 均为标准库 / Flask 内置） |
| **功能回归** | 全部通过 |

---

## 七、安全建议

1. **文件存储隔离**：上传目录不应位于 `static/` 下（Web 可直接访问）。建议将文件存储到非 Web 可访问目录，通过专用路由以 `Content-Disposition: attachment` 方式提供下载，避免 HTML 文件被浏览器渲染。

2. **Content-Type 校验**：除后缀检查外，建议增加 MIME 类型校验（使用 `file.content_type` 或 `python-magic`），防止攻击者伪造后缀。

3. **文件内容扫描**：对上传的图片文件进行内容验证（如使用 Pillow 验证文件是否为有效图片），防止图片马攻击。

4. **上传频率限制**：建议对上传接口添加频率限制（如每用户每分钟最多 5 次），防止恶意用户批量上传垃圾文件。

5. **CSP 强化**：当前 CSP 为 `default-src 'self'`，建议添加 `sandbox` 指令或设置 `X-Content-Type-Options: nosniff`（已设置），进一步降低上传文件被浏览器执行的风险。

6. **文件大小细化**：当前全局 `MAX_CONTENT_LENGTH` 适用于所有路由，建议为上传路由单独设置更小的大小限制（如图片头像通常不超过 5MB）。

---

*报告生成时间：2026年7月9日*
