#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
安全用户管理系统 — 综合安全加固版
Flask Web 应用，整合 16 项安全防护措施。

安全特性：
  1.  bcrypt 加盐密码哈希（rounds=12）
  2.  随机 Secret Key（环境变量优先）
  3.  验证码（文本混淆）+ IP 锁定 + 限流三层防爆破
  4.  密码绝不传给前端
  5.  关闭 Debug 模式
  6.  结构化审计日志（audit.log）
  7.  CSRF 令牌全局保护
  8.  Session 安全配置（HttpOnly + SameSite + 过期）
  9.  Session 固定攻击防护（登录后 session.clear()）
  10. WTForms 输入校验 + 正则白名单 + 控制字符清洗
  11. Jinja2 自动转义防 XSS
  12. 模糊错误消息防用户枚举
  13. 密码修改功能（含复杂度校验）
  14. HTTP 安全响应头
  15. SQLite 数据库存储（替代内存字典）
  16. 安全文件上传（后缀白名单 + MIME 检查 + UUID 重命名 + 路径穿越防护）
      参考：ChenMishi/claude-web-ui server/routes/fs.js
"""

import os
import re
import time
import uuid
import secrets
import sqlite3
import logging
import random
import string
from datetime import timedelta
from functools import wraps
from collections import defaultdict

import bcrypt
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, jsonify, abort
)
from flask_wtf import FlaskForm, CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import (
    StringField, PasswordField, SubmitField, EmailField
)
from wtforms.validators import (
    DataRequired, Length, Regexp, EqualTo, Email
)
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

# ============================================================
#  应用初始化 & 安全配置
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "secure_user.db")

app = Flask(__name__)

# [安全-02] 随机 Secret Key：优先环境变量，否则 256 位随机
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))

# [安全-05] 关闭 Debug 模式
app.config["DEBUG"] = False

# [安全-08] Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # 本地调试时设为 False；生产环境通过 HTTPS 部署时设为 True
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

# [安全-07] CSRF 全局保护
csrf = CSRFProtect(app)

# [安全-03c] Flask-Limiter 频率限制
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["60 per minute"],
    storage_uri="memory://",
)

# 代理修复：获取真实客户端 IP（反向代理场景）
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# [安全-16] 文件上传安全配置（参考 claude-web-ui server/routes/fs.js）
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB 限制
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
ALLOWED_MIMES = {"image/jpeg", "image/png", "image/gif", "image/webp"}

# ============================================================
#  审计日志系统
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("audit.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("secure_user")

# ============================================================
#  IP 锁定机制（防暴力破解第二层）
# ============================================================

FAILED_LOGINS = defaultdict(lambda: {"count": 0, "first_fail": 0.0})
LOCKOUT_THRESHOLD = 5
LOCKOUT_DURATION = 15 * 60  # 15 分钟


def is_ip_locked(ip):
    """检查 IP 是否被锁定"""
    record = FAILED_LOGINS.get(ip)
    if not record:
        return False
    elapsed = time.time() - record["first_fail"]
    if elapsed > LOCKOUT_DURATION:
        del FAILED_LOGINS[ip]
        return False
    return record["count"] >= LOCKOUT_THRESHOLD


def record_failed_login(ip, username):
    """记录一次失败的登录尝试"""
    record = FAILED_LOGINS[ip]
    if record["count"] == 0:
        record["first_fail"] = time.time()
    record["count"] += 1
    remaining = LOCKOUT_THRESHOLD - record["count"]
    logger.warning(
        f"[AUTH_FAIL] 用户名={username} IP={ip} "
        f"失败次数={record['count']}/剩余={remaining}"
    )
    if record["count"] >= LOCKOUT_THRESHOLD:
        logger.warning(f"[IP_LOCKED] IP={ip} 已被锁定 {LOCKOUT_DURATION // 60} 分钟")


def reset_failed_login(ip):
    """登录成功后重置失败计数"""
    if ip in FAILED_LOGINS:
        del FAILED_LOGINS[ip]


# ============================================================
#  验证码生成（防暴力破解第三层）
# ============================================================

CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # 去掉易混淆字符


def generate_captcha():
    """生成 5 位文本验证码，返回 (显示文本, 答案)"""
    answer = "".join(random.choices(CAPTCHA_CHARS, k=5))
    # 在字符间插入随机的干扰符号
    noise = ["·", "∘", "•", "⋅"]
    display = answer[0]
    for ch in answer[1:]:
        display += random.choice(noise) + ch
    return display, answer


# ============================================================
#  数据库操作
# ============================================================

def get_db():
    """获取数据库连接（请求级别复用）"""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


@app.teardown_appcontext
def close_db(error):
    """请求结束后关闭数据库连接"""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """初始化数据库：建表 + 插入默认用户"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,
            email       TEXT    NOT NULL,
            role        TEXT    NOT NULL DEFAULT 'user',
            phone       TEXT    DEFAULT '',
            balance     REAL    DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            success     INTEGER NOT NULL,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    # 插入默认用户（密码已 bcrypt 哈希）
    default_users = [
        ("admin", "Admin@2026!Secure", "admin@securesys.local", "admin", "13800138000", 99999.00),
        ("alice", "Alice@2026!Secure", "alice@securesys.local", "user",   "13900139001", 1280.50),
    ]
    for uname, pwd, email, role, phone, balance in default_users:
        existing = c.execute("SELECT id FROM users WHERE username = ?", (uname,)).fetchone()
        if not existing:
            hashed = bcrypt.hashpw(pwd.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
            c.execute(
                "INSERT INTO users (username, password, email, role, phone, balance) VALUES (?,?,?,?,?,?)",
                (uname, hashed, email, role, phone, balance),
            )
            logger.info(f"[DB_INIT] 默认用户 '{uname}' 已创建")

    conn.commit()
    conn.close()


def log_login_attempt(username, ip, success):
    """记录登录历史到数据库"""
    db = get_db()
    db.execute(
        "INSERT INTO login_history (username, ip, success) VALUES (?,?,?)",
        (username, ip, 1 if success else 0),
    )
    db.commit()


# ============================================================
#  安全辅助函数
# ============================================================

CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_input(text):
    """过滤控制字符，防止隐式注入"""
    if not text:
        return ""
    return CONTROL_CHAR_RE.sub("", text).strip()


def get_safe_user(user_row):
    """将 sqlite3.Row 转为字典，并剔除密码字段"""
    if user_row is None:
        return None
    return {
        "id":       user_row["id"],
        "username": user_row["username"],
        "email":    user_row["email"],
        "role":     user_row["role"],
        "phone":    user_row["phone"],
        "balance":  user_row["balance"],
        "created":  user_row["created_at"],
        # 注意：不返回 password 字段
    }


def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            flash("请先登录", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


# ============================================================
#  HTTP 安全响应头
# ============================================================

@app.after_request
def set_security_headers(response):
    """为每个响应添加安全头"""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


# ============================================================
#  WTForms 表单定义
# ============================================================

USERNAME_RE = r"^[a-zA-Z0-9_]{3,20}$"
PASSWORD_RE = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+]).{8,64}$"


class LoginForm(FlaskForm):
    username = StringField("用户名", validators=[
        DataRequired(message="请输入用户名"),
        Length(min=3, max=20, message="用户名长度 3~20 位"),
        Regexp(USERNAME_RE, message="用户名只能包含字母、数字、下划线"),
    ])
    password = PasswordField("密码", validators=[
        DataRequired(message="请输入密码"),
        Length(min=6, max=64, message="密码长度 6~64 位"),
    ])
    captcha = StringField("验证码", validators=[
        DataRequired(message="请输入验证码"),
    ])
    submit = SubmitField("登 录")


class RegisterForm(FlaskForm):
    username = StringField("用户名", validators=[
        DataRequired(message="请输入用户名"),
        Length(min=3, max=20, message="用户名长度 3~20 位"),
        Regexp(USERNAME_RE, message="用户名只能包含字母、数字、下划线"),
    ])
    email = EmailField("邮箱", validators=[
        DataRequired(message="请输入邮箱"),
        Email(message="邮箱格式不正确"),
    ])
    password = PasswordField("密码", validators=[
        DataRequired(message="请输入密码"),
        Length(min=8, max=64, message="密码长度 8~64 位"),
        Regexp(PASSWORD_RE, message="密码须含大小写字母、数字和特殊字符"),
    ])
    confirm = PasswordField("确认密码", validators=[
        DataRequired(message="请再次输入密码"),
        EqualTo("password", message="两次输入的密码不一致"),
    ])
    submit = SubmitField("注 册")


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField("当前密码", validators=[
        DataRequired(message="请输入当前密码"),
    ])
    new_password = PasswordField("新密码", validators=[
        DataRequired(message="请输入新密码"),
        Length(min=8, max=64, message="密码长度 8~64 位"),
        Regexp(PASSWORD_RE, message="密码须含大小写字母、数字和特殊字符"),
    ])
    confirm = PasswordField("确认新密码", validators=[
        DataRequired(message="请再次输入新密码"),
        EqualTo("new_password", message="两次输入的密码不一致"),
    ])
    submit = SubmitField("修改密码")


# ============================================================
#  路由：首页
# ============================================================

@app.route("/")
def index():
    username = session.get("username")
    if username:
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row:
            user = get_safe_user(row)
            return render_template("index.html", user=user)
        # 用户不存在（可能被删除），清除 session
        session.clear()
    return render_template("index.html", user=None)


# ============================================================
#  路由：登录
# ============================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # [安全-03a] 频率限制：5次/分钟
def login():
    client_ip = request.remote_addr or "unknown"

    # [安全-03b] IP 锁定检查
    if is_ip_locked(client_ip):
        remaining = int(LOCKOUT_DURATION - (time.time() - FAILED_LOGINS[client_ip]["first_fail"]))
        flash(f"该 IP 登录失败次数过多，已被临时锁定，请 {remaining // 60} 分钟后再试", "error")
        logger.warning(f"[BLOCKED] 被锁定 IP={client_ip} 尝试访问登录页")
        return render_template("login.html", form=LoginForm(), captcha=None, locked=True)

    form = LoginForm()

    if request.method == "GET":
        # 生成验证码
        display, answer = generate_captcha()
        session["captcha_answer"] = answer
        return render_template("login.html", form=form, captcha=display)

    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        captcha_input = (form.captcha.data or "").strip().upper()

        # [安全-03c] 验证码校验
        expected = session.pop("captcha_answer", None)
        if not expected or captcha_input != expected:
            flash("验证码错误", "error")
            logger.warning(f"[CAPTCHA_FAIL] IP={client_ip} 用户名={username}")
            # 刷新验证码
            display, answer = generate_captcha()
            session["captcha_answer"] = answer
            return render_template("login.html", form=form, captcha=display)

        password = form.password.data

        # 数据库查询用户
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        # [安全-01] bcrypt 密码验证
        if row and bcrypt.checkpw(password.encode("utf-8"), row["password"].encode("utf-8")):
            # 登录成功
            reset_failed_login(client_ip)
            log_login_attempt(username, client_ip, True)

            # [安全-09] Session 固定攻击防护：清除旧 session
            session.clear()
            session.permanent = True
            session["username"] = username
            session["login_time"] = int(time.time())

            logger.info(f"[AUTH_OK] 用户='{username}' IP={client_ip} 登录成功")
            flash("登录成功", "success")
            return redirect(url_for("index"))

        # 登录失败
        record_failed_login(client_ip, username)
        log_login_attempt(username, client_ip, False)

        # [安全-12] 模糊错误消息，不区分"用户不存在"和"密码错误"
        remaining = max(0, LOCKOUT_THRESHOLD - FAILED_LOGINS[client_ip]["count"])
        flash(f"用户名或密码错误（剩余尝试 {remaining} 次）", "error")

    # 重新生成验证码
    display, answer = generate_captcha()
    session["captcha_answer"] = answer
    return render_template("login.html", form=form, captcha=display)


# ============================================================
#  路由：注册
# ============================================================

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute")
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = sanitize_input(form.username.data)
        email = sanitize_input(form.email.data)
        password = form.password.data

        db = get_db()

        # 检查用户名是否已存在
        existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("该用户名已被注册", "error")
            return render_template("register.html", form=form)

        # [安全-01] bcrypt 哈希
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
        db.execute(
            "INSERT INTO users (username, password, email, role, phone, balance) VALUES (?,?,?,?,?,?)",
            (username, hashed, email, "user", "", 0.00),
        )
        db.commit()
        logger.info(f"[REGISTER] 新用户注册 用户名='{username}' 邮箱={email} IP={request.remote_addr}")
        flash("注册成功，请登录", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


# ============================================================
#  路由：修改密码
# ============================================================

@app.route("/change_password", methods=["GET", "POST"])
@login_required
@limiter.limit("3 per minute")
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        old_password = form.old_password.data
        new_password = form.new_password.data

        db = get_db()
        row = db.execute("SELECT password FROM users WHERE username = ?", (session["username"],)).fetchone()

        if not row or not bcrypt.checkpw(old_password.encode("utf-8"), row["password"].encode("utf-8")):
            flash("当前密码不正确", "error")
            return render_template("change_password.html", form=form)

        # 新密码不能与旧密码相同
        if bcrypt.checkpw(new_password.encode("utf-8"), row["password"].encode("utf-8")):
            flash("新密码不能与当前密码相同", "error")
            return render_template("change_password.html", form=form)

        hashed = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")
        db.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, session["username"]))
        db.commit()

        logger.info(f"[PWD_CHANGE] 用户='{session['username']}' 修改密码成功 IP={request.remote_addr}")
        flash("密码修改成功，请重新登录", "success")
        session.clear()
        return redirect(url_for("login"))

    return render_template("change_password.html", form=form)


# ============================================================
#  路由：登录历史
# ============================================================

@app.route("/login_history")
@login_required
def login_history():
    db = get_db()
    rows = db.execute(
        "SELECT * FROM login_history WHERE username = ? ORDER BY id DESC LIMIT 20",
        (session["username"],),
    ).fetchall()
    records = [
        {"ip": r["ip"], "success": bool(r["success"]), "time": r["timestamp"]}
        for r in rows
    ]
    return render_template("login_history.html", records=records)


# ============================================================
#  路由：登出
# ============================================================

@app.route("/logout")
def logout():
    username = session.get("username", "unknown")
    session.clear()
    logger.info(f"[LOGOUT] 用户='{username}' 登出 IP={request.remote_addr}")
    flash("已安全退出", "info")
    return redirect(url_for("login"))


# ============================================================
#  路由：头像上传（安全版 — 参考 claude-web-ui fs.js）
# ============================================================

@app.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def upload():
    """安全的头像上传：类型检查 + 文件名清理 + UUID 重命名"""
    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or file.filename == "":
            flash("请选择要上传的文件", "error")
            return redirect(url_for("upload"))

        filename = file.filename

        # [安全-16a] 文件后缀白名单检查
        ext = os.path.splitext(filename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            flash(f"不支持的文件类型: {ext}，仅允许 {', '.join(ALLOWED_EXTENSIONS)}", "error")
            logger.warning(f"[UPLOAD_REJECT] 用户='{session['username']}' 文件={filename} 原因=后缀不允许")
            return redirect(url_for("upload"))

        # [安全-16b] MIME 类型检查
        mime = file.content_type or ""
        if mime not in ALLOWED_MIMES:
            flash(f"不支持的文件类型（MIME: {mime}）", "error")
            logger.warning(f"[UPLOAD_REJECT] 用户='{session['username']}' 文件={filename} 原因=MIME不允许")
            return redirect(url_for("upload"))

        # [安全-16c] 文件名清理 + UUID 重命名
        # 参考 claude-web-ui: baseName.replace(/[\/\\\x00-\x1f\x7f]/g, '_') + 时间戳
        safe_base = secure_filename(os.path.splitext(filename)[0]) or "avatar"
        safe_name = f"{session['username']}_{uuid.uuid4().hex[:8]}{ext}"
        filepath = os.path.join(UPLOAD_DIR, safe_name)

        # [安全-16d] 防止路径穿越：确保最终路径在 UPLOAD_DIR 内
        if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_DIR)):
            flash("文件路径异常", "error")
            logger.warning(f"[UPLOAD_REJECT] 用户='{session['username']}' 路径穿越尝试: {filename}")
            return redirect(url_for("upload"))

        file.save(filepath)
        file_url = url_for("static", filename=f"uploads/{safe_name}")

        logger.info(f"[UPLOAD_OK] 用户='{session['username']}' 原文件={filename} → 保存为={safe_name} IP={request.remote_addr}")
        flash("头像上传成功", "success")
        return render_template("upload.html", file_url=file_url, filename=safe_name)

    return render_template("upload.html")


# ============================================================
#  错误处理
# ============================================================

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="页面不存在"), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="访问被拒绝"), 403


@app.errorhandler(429)
def rate_limited(e):
    return render_template("error.html", code=429, message="请求过于频繁，请稍后再试"), 429


@app.errorhandler(500)
def server_error(e):
    logger.error(f"[SERVER_ERROR] {e}")
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ============================================================
#  入口
# ============================================================

if __name__ == "__main__":
    init_db()
    # 生产环境应使用 gunicorn / uwsgi，这里仅用于本地调试
    app.run(host="127.0.0.1", port=5000, debug=False)
