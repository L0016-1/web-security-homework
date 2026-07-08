# 安全审计与漏洞修复报告

> **项目名称**：安全用户管理系统（SecureUser System）
> **审计日期**：2026-07-07
> **审计目标**：Flask 用户信息管理平台
> **风险等级**：🔴 严重（修复前）
> **报告版本**：v1.0

---

## 目录

1. [审计概述](#1-审计概述)
2. [漏洞汇总](#2-漏洞汇总)
3. [严重漏洞详解](#3-严重漏洞详解)
4. [高危漏洞详解](#4-高危漏洞详解)
5. [中危漏洞详解](#5-中危漏洞详解)
6. [低危漏洞详解](#6-低危漏洞详解)
7. [修复方案对照表](#7-修复方案对照表)
8. [OWASP Top 10 映射](#8-owasp-top-10-映射)
9. [安全建议](#9-安全建议)
10. [测试验证](#10-测试验证)

---

## 1. 审计概述

本报告针对一个 Flask 用户管理系统进行安全审计。该系统在**修复前**存在多处安全漏洞，涵盖密码存储、会话管理、输入校验、配置安全、SQL 注入等多个维度。经过系统性修复，共修补 **20 项安全漏洞**，覆盖了从严重到低危的各个等级。

**审计范围**：
- 应用源代码（`app.py`）
- 前端模板（`templates/*.html`）
- 依赖配置（`requirements.txt`）
- 运行时配置（Flask 配置项）

---

## 2. 漏洞汇总

| 编号 | 漏洞名称 | 风险等级 | 简要描述 |
|------|---------|---------|---------|
| V-01 | **密码明文存储** | 🔴 严重 | 密码以明文形式存储在数据源中 |
| V-02 | **密码明文显示在页面** | 🔴 严重 | 登录后用户密码被直接渲染到 HTML 页面 |
| V-03 | **硬编码弱密钥** | 🔴 严重 | `secret_key` 为硬编码弱字符串 |
| V-04 | **无暴力破解防护** | 🔴 严重 | 登录接口可无限次尝试，无频率限制 |
| V-05 | **HTML 注释泄露凭证** | 🟠 高危 | 模板 HTML 注释中包含管理员账号密码 |
| V-06 | **Debug 模式开启** | 🟠 高危 | `debug=True` 暴露 Werkzeug 调试器 |
| V-07 | **无 CSRF 保护** | 🟠 高危 | 表单缺少 CSRF 令牌 |
| V-08 | **无 Session 安全配置** | 🟠 高危 | Cookie 缺少 HttpOnly、SameSite 等属性 |
| V-09 | **无输入校验** | 🟡 中危 | 用户输入未做格式校验和字符清洗 |
| V-10 | **Session 固定攻击** | 🟡 中危 | 登录后未重新生成 Session ID |
| V-11 | **无审计日志** | 🟡 中危 | 安全事件无记录，无法追溯 |
| V-12 | **错误消息泄露用户名** | 🟡 中危 | 登录失败消息可区分"用户不存在"和"密码错误" |
| V-13 | **无密码修改功能** | 🟢 低危 | 用户无法自助修改密码 |
| V-14 | **缺少安全响应头** | 🟢 低危 | 未设置 X-Frame-Options 等安全头 |
| V-15 | **内存字典存储用户** | 🟢 低危 | 用户数据存内存，重启丢失 |
| V-16 | **SQL 注入（注册接口）** | 🔴 严重 | `/register` 用 f-string 拼接 SQL，可注入任意数据或执行危险操作 |
| V-17 | **SQL 注入（搜索接口）** | 🔴 严重 | `/search` 用 f-string 拼接 SQL，可 UNION 注入窃取全库数据 |
| V-18 | **搜索接口越权访问** | 🟠 高危 | `/search` 未检查登录状态，未登录可直接搜索用户数据 |
| V-19 | **注册无密码复杂度校验** | 🟡 中危 | 注册接受任意弱密码（如 `1`），无长度/复杂度要求 |
| V-20 | **注册/搜索无输入校验** | 🟡 中危 | 用户名/邮箱/手机号均无格式校验和字符白名单 |

---

## 3. 严重漏洞详解

### V-01：密码明文存储 🔴

**位置**：`app.py` — `USERS` 数据源

**问题代码**：
```python
USERS = {
    "admin": {
        "password": "admin123",   # ← 明文存储
    },
    "alice": {
        "password": "alice2025",  # ← 明文存储
    }
}
```

**风险分析**：
- 数据源泄露后，所有用户密码直接暴露
- 用户习惯复用密码，可导致撞库攻击（Credential Stuffing）
- 违反《网络安全法》和等级保护要求

**利用方式**：
攻击者通过任意文件读取漏洞、源码泄露、或内部人员权限获取到 `USERS` 字典后，可直接读取所有用户的明文密码，进而尝试登录该用户的其他系统账号（邮箱、社交平台等）。

**修复方案**：
使用 `bcrypt` 库进行加盐哈希存储，计算成本参数设为 12 轮（行业标准）。

**修复后代码**：
```python
import bcrypt

# 存储时：生成哈希
password_hash = bcrypt.hashpw(
    "Admin@2026!Secure".encode("utf-8"),
    bcrypt.gensalt(rounds=12)
).decode("utf-8")

# 验证时：恒定时间比较
if bcrypt.checkpw(input_password.encode("utf-8"), stored_hash.encode("utf-8")):
    # 密码正确
```

**为何选择 bcrypt？**
- 自带盐值（每次哈希结果不同），抗彩虹表攻击
- 可调计算成本（rounds），随硬件升级可增强
- 抗 GPU/ASIC 并行破解（相比 MD5/SHA-256）

---

### V-02：密码明文显示在页面 🔴

**位置**：`app.py` 第 31 行 & `templates/index.html`

**问题代码**：
```python
# app.py — 完整用户对象（含密码）传给模板
return render_template("index.html", user=user)
```
```html
<!-- index.html — 直接渲染密码 -->
<li>密码: {{ user['password'] }}</li>
```

**风险分析**：
- 登录后密码直接显示在页面上
- 旁人路过即可看到密码（Shoulder Surfing）
- 截图分享时意外泄露密码

**修复方案**：
在渲染前使用 `get_safe_user()` 函数过滤密码字段，模板中密码位置显示 `••••••••`。

**修复后代码**：
```python
def get_safe_user(user_row):
    """返回不含密码的安全用户信息"""
    return {
        "username": user_row["username"],
        "email":    user_row["email"],
        "role":     user_row["role"],
        # 不返回 password 字段
    }
```
```html
<li>密码: <span class="password-masked">••••••••••</span></li>
```

---

### V-03：硬编码弱密钥 🔴

**位置**：`app.py` 第 5 行

**问题代码**：
```python
app.secret_key = "dev-key-2025"  # ← 硬编码、弱、可预测
```

**风险分析**：
- 密钥强度极低，可被暴力破解或猜测
- Flask Session Cookie 使用此密钥签名，攻击者知道密钥后可伪造任意用户的 Session
- 导致完全的会话劫持和身份伪造

**利用方式**：
```python
# 攻击者利用已知密钥伪造管理员 Session
from flask.sessions import SecureCookieSessionInterface
# 构造 {"username": "admin"} 的 Session Cookie
# 用已知密钥签名后发送给服务器 → 免密登录
```

**修复方案**：
优先从环境变量读取密钥，否则使用 `secrets.token_hex(32)` 生成 256 位随机密钥。

**修复后代码**：
```python
import os, secrets
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
```

---

### V-04：无暴力破解防护 🔴

**位置**：`app.py` — `/login` 路由

**问题代码**：
```python
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # 无频率限制、无验证码、无IP锁定
        # 攻击者可无限次尝试密码
        if check_password(username, password):
            ...
```

**风险分析**：
- 攻击者可使用 Burp Suite Intruder、Hydra 等工具进行字典爆破
- 弱密码可在数分钟内被破解

**利用方式**：
```bash
# 使用 Hydra 爆破
hydra -l admin -P rockyou.txt http-post-form \
  "/login:username=^USER^&password=^PASS^:F=密码错误"
```

**修复方案**：
实施三层防护：

| 层级 | 措施 | 实现 |
|------|------|------|
| 第1层 | 频率限制 | `@limiter.limit("5 per minute")` |
| 第2层 | IP 锁定 | 5次失败后锁定该 IP 15分钟 |
| 第3层 | 验证码 | 文本验证码，防自动化工具 |

**修复后代码**：
```python
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")           # 第1层
def login():
    if is_ip_locked(client_ip):           # 第2层
        flash("IP 已被锁定")
        ...
    # 验证码校验                            # 第3层
    if captcha_input != session.pop("captcha_answer"):
        flash("验证码错误")
        ...
```

---

## 4. 高危漏洞详解

### V-05：HTML 注释泄露管理员凭证 🟠

**位置**：`templates/login.html`

**问题代码**：
```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

**风险分析**：
- 任何用户在浏览器中查看页面源代码即可获得管理员凭证
- 即使后续修改了密码，注释也可能未同步更新

**利用方式**：
浏览器右键 → 查看源代码 → 搜索 "admin" → 获取账号密码。

**修复方案**：
删除所有包含敏感信息的 HTML 注释，默认账号通过初始化脚本管理。

---

### V-06：Debug 模式开启 🟠

**位置**：`app.py` 末尾

**问题代码**：
```python
app.run(debug=True, host="0.0.0.0", port=5000)
```

**风险分析**：
- `debug=True` 启用 Werkzeug 调试器
- 调试器允许在浏览器中执行任意 Python 代码（RCE）
- 错误页面会显示完整调用栈、源代码片段、环境变量

**利用方式**：
访问触发异常的 URL → Werkzeug 调试器页面 → 在 Python 控制台输入 `import os; os.system("whoami")` → 获取服务器控制权。

**修复方案**：
```python
app.config["DEBUG"] = False
app.run(host="127.0.0.1", port=5000, debug=False)
```

---

### V-07：无 CSRF 保护 🟠

**位置**：`templates/login.html` — 表单

**问题代码**：
```html
<form method="POST" action="/login">
  <!-- 缺少 CSRF 令牌 -->
  <input name="username">
  <input name="password">
</form>
```

**风险分析**：
攻击者可构造恶意网页，诱导已登录用户访问后自动提交表单。

**利用方式**：
```html
<!-- 攻击者的恶意页面 -->
<form action="http://victim.com/change_password" method="POST">
  <input name="old_password" value="known">
  <input name="new_password" value="hacked">
</form>
<script>document.forms[0].submit()</script>
```

**修复方案**：
集成 Flask-WTF 的 `CSRFProtect`，所有 POST 表单包含 `{{ form.hidden_tag() }}`。

```python
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)
```
```html
<form method="POST">
  {{ form.hidden_tag() }}  <!-- 自动插入 CSRF 令牌 -->
  ...
</form>
```

---

### V-08：无 Session 安全配置 🟠

**位置**：`app.py` — Flask 配置

**缺失的配置**：
```python
# 原代码完全没有以下配置
SESSION_COOKIE_HTTPONLY = True     # 防止 JS 通过 document.cookie 读取
SESSION_COOKIE_SAMESITE = "Lax"   # 防 CSRF
PERMANENT_SESSION_LIFETIME = ...   # Session 过期时间
```

**修复方案**：
```python
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
)
```

---

## 5. 中危漏洞详解

### V-09：无输入校验 🟡

**位置**：`app.py` — 登录路由

**问题代码**：
```python
username = request.form.get("username", "").strip()
# 无格式校验、无长度限制、无字符白名单
```

**风险分析**：
- XSS 注入（`<script>alert(1)</script>` 作为用户名）
- 控制字符注入（零宽字符、换行注入）
- 超长输入导致 DoS

**修复方案**：
三层校验 — WTForms 正则白名单 + 控制字符清洗 + Jinja2 自动转义。

```python
# WTForms 正则白名单
username = StringField("用户名", validators=[
    Regexp(r"^[a-zA-Z0-9_]{3,20}$")
])

# 控制字符清洗
def sanitize_input(text):
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text).strip()

# Jinja2 自动转义（Flask 默认开启）
{{ user.username }}  ← 自动转义 HTML
```

---

### V-10：Session 固定攻击 🟡

**问题**：登录成功后沿用同一个 Session ID。

**利用方式**：
1. 攻击者访问网站获得一个 Session ID
2. 通过钓鱼链接让用户使用该 Session ID 登录
3. 用户登录后，攻击者使用同一 Session ID 即可登录

**修复方案**：
```python
# 登录成功后清除旧 session，生成新 session
session.clear()
session["username"] = username
```

---

### V-11：无审计日志 🟡

**问题**：所有安全事件（登录成功/失败、密码修改、IP锁定等）均无记录。

**修复方案**：
使用 Python `logging` 模块，结构化记录所有安全事件到 `audit.log`。

```python
logging.basicConfig(
    handlers=[logging.FileHandler("audit.log"), logging.StreamHandler()],
)
logger = logging.getLogger("secure_user")

# 记录事件
logger.info(f"[AUTH_OK] 用户='{username}' IP={ip} 登录成功")
logger.warning(f"[AUTH_FAIL] 用户名={username} IP={ip} 失败次数={n}")
logger.warning(f"[IP_LOCKED] IP={ip} 已被锁定")
logger.info(f"[PWD_CHANGE] 用户='{username}' 修改密码成功")
```

---

### V-12：错误消息泄露用户名 🟡

**问题代码**：
```python
if not user:
    flash("用户名不存在")        # ← 泄露用户名是否存在
elif not check_password(...):
    flash("密码错误")           # ← 确认用户名存在
```

**修复方案**：
统一返回模糊错误消息，不区分具体原因。

```python
flash("用户名或密码错误（剩余尝试 N 次）")
```

---

## 6. 低危漏洞详解

### V-13：无密码修改功能 🟢

**问题**：用户密码泄露后无法自助修改。

**修复方案**：新增 `/change_password` 路由，包含：
- 旧密码验证（bcrypt 比对）
- 新密码复杂度校验（正则：大小写+数字+特殊字符）
- 新旧密码不能相同
- 修改后强制重新登录

---

### V-14：缺少安全响应头 🟢

**问题**：未设置 `X-Frame-Options`、`X-Content-Type-Options` 等安全头。

**修复方案**：
```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=()"
    return response
```

---

### V-15：内存字典存储用户 🟢

**问题**：用户数据存内存字典，应用重启后数据丢失，且无法持久化。

**修复方案**：
使用 SQLite 数据库替代内存字典，包含 `users` 和 `login_history` 两张表。

```python
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db
```

---

## 6.5 新增漏洞详解（V2 版本代码新增）

> 以下漏洞为原始代码第二版（新增注册/搜索功能后）引入的安全问题。

### V-16：SQL 注入（注册接口）🔴

**位置**：`app.py` — `/register` 路由

**问题代码**：
```python
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        # ↓ f-string 直接拼接 SQL，典型注入漏洞
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        c.execute(sql)
```

**风险分析**：
- 攻击者可通过注册表单注入任意 SQL 语句
- 可删除整张用户表、插入管理员账户、或利用 SQLite 的 ATTACH 读取其他数据库文件

**利用方式**：
```
# 注册表单用户名填入：
admin', 'hacked', 'a@b.com', '123'); DROP TABLE users; --

# 拼接后的 SQL：
INSERT INTO users (username, password, email, phone)
VALUES ('admin', 'hacked', 'a@b.com', '123'); DROP TABLE users; --', ...)
```

**修复方案**：使用参数化查询（`?` 占位符）。
```python
c.execute(
    "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
    (username, password, email, phone)
)
```

---

### V-17：SQL 注入（搜索接口）🔴

**位置**：`app.py` — `/search` 路由

**问题代码**：
```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    # ↓ f-string 拼接，且 keyword 来自用户输入
    sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
    c.execute(sql)
```

**风险分析**：
- 比 V-16 更危险——搜索接口直接返回查询结果，攻击者可通过 UNION 注入逐条读取所有用户数据
- 即使密码不在查询字段中，也可通过 UNION 获取 `password` 列

**利用方式**：
```
# 搜索框输入：
' UNION SELECT id, username, password, phone FROM users --

# 拼接后的 SQL：
SELECT id, username, email, phone FROM users
WHERE username LIKE '%' UNION SELECT id, username, password, phone FROM users --%'
```

**修复方案**：
```python
c.execute(
    "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
    (f"%{keyword}%", f"%{keyword}%")
)
```

---

### V-18：搜索接口越权访问 🟠

**位置**：`app.py` — `/search` 路由

**问题代码**：
```python
@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    # ↓ 没有检查 session["username"] 是否存在
    # 即使未登录，只要带 keyword 参数就会执行搜索
    if keyword:
        c.execute(sql)
```

**风险分析**：
- `/search` 路由没有登录验证，任何人无需登录即可搜索并获取所有用户信息
- 虽然 `index.html` 只在登录后才显示搜索框，但直接访问 `/search?keyword=admin` 可绕过前端限制

**修复方案**：添加 `login_required` 装饰器或登录检查。
```python
@app.route("/search")
@login_required
def search():
    ...
```

---

### V-19：注册无密码复杂度校验 🟡

**位置**：`app.py` — `/register` 路由

**问题代码**：
```python
password = request.form.get("password", "")
# 无任何校验，直接存入数据库
c.execute(sql)  # 密码 "1" 也能注册成功
```

**修复方案**：使用正则校验密码复杂度。
```python
import re
if not re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%]).{8,64}$", password):
    error = "密码必须8位以上，含大小写字母、数字和特殊字符"
```

---

### V-20：注册/搜索无输入校验 🟡

**位置**：`app.py` — `/register` 和 `/search` 路由

**问题**：`username`、`email`、`phone` 均无格式校验和长度限制，可注入超长字符串、特殊字符、控制字符。

**修复方案**：使用 WTForms 正则白名单 + 长度限制。


| 编号 | 漏洞 | 等级 | 修复措施 | 状态 |
|------|------|------|---------|------|
| V-01 | 密码明文存储 | 🔴严重 | bcrypt 加盐哈希（rounds=12） | ✅ |
| V-02 | 密码明文显示 | 🔴严重 | `get_safe_user()` 过滤密码字段 | ✅ |
| V-03 | 硬编码弱密钥 | 🔴严重 | 环境变量 + `secrets.token_hex(32)` | ✅ |
| V-04 | 无暴力破解防护 | 🔴严重 | 三层防护（限流+IP锁定+验证码） | ✅ |
| V-05 | HTML 注释泄露 | 🟠高危 | 删除所有敏感注释 | ✅ |
| V-06 | Debug 模式 | 🟠高危 | `debug=False` | ✅ |
| V-07 | 无 CSRF 保护 | 🟠高危 | Flask-WTF `CSRFProtect` | ✅ |
| V-08 | Session 安全 | 🟠高危 | HttpOnly+SameSite+过期时间 | ✅ |
| V-09 | 无输入校验 | 🟡中危 | WTForms 正则 + 控制字符清洗 | ✅ |
| V-10 | Session 固定 | 🟡中危 | 登录后 `session.clear()` | ✅ |
| V-11 | 无审计日志 | 🟡中危 | `logging` → `audit.log` | ✅ |
| V-12 | 错误消息泄露 | 🟡中危 | 统一模糊错误消息 | ✅ |
| V-13 | 无密码修改 | 🟢低危 | 新增 `/change_password` 路由 | ✅ |
| V-14 | 缺安全头 | 🟢低危 | `after_request` 设置安全头 | ✅ |
| V-15 | 内存存储 | 🟢低危 | SQLite 数据库 | ✅ |
| V-16 | SQL 注入（注册） | 🔴严重 | 参数化查询 `?` 占位符 | ✅ |
| V-17 | SQL 注入（搜索） | 🔴严重 | 参数化查询 `?` 占位符 | ✅ |
| V-18 | 搜索越权访问 | 🟠高危 | `login_required` 装饰器 | ✅ |
| V-19 | 注册无密码校验 | 🟡中危 | 正则复杂度校验 | ✅ |
| V-20 | 注册无输入校验 | 🟡中危 | WTForms 正则白名单 | ✅ |

---

## 8. OWASP Top 10 映射

| 漏洞编号 | OWASP 分类 | 说明 |
|---------|-----------|------|
| V-01, V-02 | **A02:2021 — 加密机制失效** | 密码未加密存储和传输 |
| V-03, V-06, V-08, V-14 | **A05:2021 — 安全配置错误** | 弱密钥、Debug模式、Session配置、安全头 |
| V-05 | **A01:2021 — 失效的访问控制** | 调试信息泄露凭证 |
| V-07 | **A04:2021 — 不安全的设计** | 缺少 CSRF 防护 |
| V-04 | **A07:2021 — 身份认证失效** | 无暴力破解防护 |
| V-09 | **A03:2021 — 注入** | 输入校验缺失（XSS 风险） |
| V-10 | **A07:2021 — 身份认证失效** | Session 固定攻击 |
| V-11, V-12 | **A09:2021 — 安全日志与监控失效** | 无审计日志、错误消息泄露 |
| V-15 | **A04:2021 — 不安全的设计** | 内存存储，无持久化 |
| V-16, V-17 | **A03:2021 — 注入** | SQL 注入（f-string 拼接） |
| V-18 | **A01:2021 — 失效的访问控制** | 搜索接口未鉴权 |
| V-19, V-20 | **A07:2021 — 身份认证失效 / A03:2021 — 注入** | 无密码复杂度校验、无输入校验 |

---

## 9. 安全建议

### 短期（立即执行）

1. 🔴 使用 bcrypt 加盐哈希存储所有密码
2. 🔴 删除密码明文显示功能
3. 🔴 更换 `secret_key` 为强随机密钥
4. 🔴 关闭 Debug 模式
5. 🔴 实施登录频率限制

### 中期（1-2 周内）

1. 🟠 集成 CSRF 全局保护
2. 🟠 配置完整的 Session 安全选项
3. 🟠 添加验证码机制
4. 🟠 实现 IP 锁定策略
5. 🟡 部署审计日志系统
6. 🟡 实施输入校验和清洗

### 长期（架构层面）

1. 使用专业数据库（MySQL/PostgreSQL）替代 SQLite
2. 集成 OAuth2 / SSO 单点登录
3. 部署 HTTPS（Let's Encrypt + Nginx）
4. 实施双因素认证（TOTP）
5. 定期进行安全渗透测试
6. 集成 SIEM 日志分析平台
7. 实施内容安全策略（CSP）

---

## 10. 测试验证

### 测试用例

| 测试项 | 测试方法 | 预期结果 |
|--------|---------|---------|
| 密码哈希 | 查看 `secure_user.db` 中 `password` 字段 | 应为 bcrypt 哈希（`$2b$12$...`） |
| 暴力破解 | 连续5次输入错误密码 | 第6次显示"IP 已被锁定" |
| 频率限制 | 1分钟内发送6次登录请求 | 第6次返回 429 状态码 |
| 验证码 | 不填或填错验证码 | 提示"验证码错误" |
| CSRF | 禁用 Cookie 后提交表单 | 返回 400 Bad Request |
| Session 固定 | 记录登录前 Session ID | 登录后 Session ID 应改变 |
| XSS | 用户名输入 `<script>alert(1)</script>` | 页面显示原文，不执行脚本 |
| 密码显示 | 登录后查看首页 | 密码显示为 `••••••••` |
| 错误消息 | 分别输入不存在用户和错误密码 | 返回相同的错误消息 |
| 审计日志 | 执行登录/登出操作后查看 `audit.log` | 应包含对应事件记录 |
| 安全头 | 检查 HTTP 响应头 | 包含 X-Frame-Options 等 |
| Session 过期 | 登录后等待30分钟 | Session 自动过期，需重新登录 |
| SQL 注入（注册） | 注册用户名填 `test', 'pw', 'a@b', '1'); DROP TABLE users; --` | 注册失败，数据库不受影响 |
| SQL 注入（搜索） | 搜索框填 `' UNION SELECT id,username,password,phone FROM users --` | 返回空结果，不泄露密码 |
| 搜索越权 | 未登录直接访问 `/search?keyword=admin` | 重定向到登录页 |

---

> **免责声明**：本报告仅用于安全学习和课程作业目的。
