# 🔒 Web 用户管理系统 — 安全漏洞分析与修复

> 网络安全课程作业：对一个存在多项安全漏洞的 Flask 用户管理系统进行漏洞分析、修复与安全加固。

## 📌 项目简介

本项目包含一个 **原始漏洞版本** 和一个 **安全加固版本** 的 Flask 用户管理系统。原始版本存在 **15 项安全漏洞**，涵盖 OWASP Top 10 中的 7 个类别。安全加固版本对所有漏洞进行了系统性修复，并新增了用户注册、登录历史、密码修改等功能。

## 📁 项目结构

```
web-security-homework/
├── original/                     # 原始漏洞版本
│   ├── app.py                    # Flask 主程序（含 15 项漏洞）
│   ├── templates/
│   │   ├── base.html             # 基础模板
│   │   ├── index.html            # 首页（密码明文展示）
│   │   └── login.html            # 登录页（HTML 注释泄露凭证）
│   └── static/
│       └── css/
│           └── style.css         # 样式文件
├── patched/                      # 安全加固版本
│   ├── app.py                    # Flask 主程序（15 项安全防护）
│   ├── init_db.py                # 数据库初始化脚本
│   ├── requirements.txt          # Python 依赖
│   ├── templates/
│   │   ├── base.html             # 基础模板（含 CSRF 令牌）
│   │   ├── login.html            # 登录页（验证码 + CSRF）
│   │   ├── register.html         # 注册页（密码复杂度校验）
│   │   ├── index.html            # 首页（密码不传前端）
│   │   ├── change_password.html  # 修改密码页
│   │   ├── login_history.html    # 登录历史页
│   │   └── error.html            # 错误页面（404/403/429/500）
│   └── static/
│       └── css/
│           └── style.css         # 蓝靛色主题样式
├── docs/
│   ├── SECURITY_REPORT.md        # 详细安全审计报告
│   └── 修复方案对比.md            # 与参考修复方案的对比分析
├── README.md                     # 本文件
└── .gitignore
```

## 🐛 漏洞总览

| # | 漏洞名称 | 风险等级 | OWASP Top 10 | 所在文件 |
|---|---------|---------|--------------|---------|
| 1 | 明文密码存储 | 🔴 严重 | A02:2021 加密失败 | `app.py` |
| 2 | 弱 Secret Key | 🔴 严重 | A02:2021 加密失败 | `app.py` |
| 3 | 密码明文展示在前端 | 🔴 严重 | A01:2021 访问控制失效 | `index.html` |
| 4 | 无暴力破解防护 | 🔴 严重 | A07:2021 身份认证失败 | `app.py` |
| 5 | Debug 模式开启 | 🟠 高危 | A05:2021 安全配置错误 | `app.py` |
| 6 | 无审计日志 | 🟠 高危 | A09:2021 日志监控不足 | `app.py` |
| 7 | 无 CSRF 防护 | 🟡 中危 | A01:2021 访问控制失效 | `login.html` |
| 8 | Session 安全配置缺失 | 🟡 中危 | A05:2021 安全配置错误 | `app.py` |
| 9 | Session 固定攻击 | 🟡 中危 | A07:2021 身份认证失败 | `app.py` |
| 10 | 无输入校验与过滤 | 🟡 中危 | A03:2021 注入 | `app.py` |
| 11 | HTML 注释泄露凭证 | 🟡 中危 | A05:2021 安全配置错误 | `login.html` |
| 12 | 无 HTTP 安全响应头 | 🟡 中危 | A05:2021 安全配置错误 | `app.py` |
| 13 | 无密码修改功能 | 🟢 低危 | A07:2021 身份认证失败 | `app.py` |
| 14 | 错误消息可枚举用户 | 🟢 低危 | A07:2021 身份认证失败 | `app.py` |
| 15 | 数据仅存内存无持久化 | 🟢 低危 | A04:2021 不安全设计 | `app.py` |

> 详细分析见 [docs/SECURITY_REPORT.md](docs/SECURITY_REPORT.md)

## 🚀 快速开始

### 运行原始漏洞版本（仅供分析）

```bash
cd original
pip install flask
python app.py
# 访问 http://127.0.0.1:5000
# 测试账号: admin / admin123
```

⚠️ **警告**：此版本存在严重安全漏洞，仅用于漏洞分析，切勿在生产环境运行！

### 运行安全加固版本

```bash
cd patched
pip install -r requirements.txt
python init_db.py     # 初始化数据库
python app.py         # 启动应用
# 访问 http://127.0.0.1:5000
# 测试账号: admin / Admin@2026!Secure
```

## 🛡️ 安全加固措施

| 措施 | 说明 |
|------|------|
| bcrypt 加盐哈希 | 密码使用 bcrypt（rounds=12）哈希存储，抗彩虹表 |
| 随机 Secret Key | 256 位随机密钥，环境变量优先 |
| 三层防爆破 | 限流（5次/分）+ IP 锁定（5次失败锁15分钟）+ 验证码 |
| CSRF 全局保护 | Flask-WTF CSRFProtect 全站防护 |
| Session 安全 | HttpOnly + SameSite=Lax + 30分钟过期 |
| Session 固定防护 | 登录后 `session.clear()` 重新生成 |
| WTForms 输入校验 | 正则白名单 + 长度限制 + 控制字符清洗 |
| 审计日志 | 所有安全事件写入 `audit.log` |
| 密码修改功能 | 含旧密码验证 + 复杂度校验 |
| 安全响应头 | X-Frame-Options / X-Content-Type-Options 等 6 项 |
| SQLite 数据库 | 替代内存字典，支持持久化 |
| 用户注册 | 含密码复杂度校验 + 用户名查重 |
| 登录历史 | 记录所有登录尝试，用户可查看 |
| 错误处理 | 404/403/429/500 自定义错误页 |
| 密码不传前端 | `get_safe_user()` 剔除密码字段 |

## 📊 修复方案对比

> 详细对比见 [docs/修复方案对比.md](docs/修复方案对比.md)

| 对比项 | 本项目 | 参考方案 A | 参考方案 B |
|--------|--------|-----------|-----------|
| 漏洞修复数 | **15 项** | 13 项 | 11 项 |
| 数据存储 | SQLite 数据库 | 内存字典 | 内存字典 |
| 密码哈希 | bcrypt (rounds=12) | bcrypt | Werkzeug |
| 防爆破层数 | 3 层 | 3 层 | 1 层 |
| 用户注册 | ✅ | ❌ | ❌ |
| 登录历史 | ✅ | ❌ | ❌ |
| 安全响应头 | ✅ 6 项 | ❌ | ❌ |
| 审计日志 | ✅ | ✅ | ❌ |
| OWASP 映射 | ✅ | ❌ | ✅ |

## 📝 技术栈

- **后端**：Python 3.10+ / Flask 3.x
- **数据库**：SQLite 3
- **安全库**：bcrypt / Flask-WTF / Flask-Limiter / WTForms
- **前端**：HTML5 / CSS3 / Jinja2 模板引擎

## 📄 许可证

本项目仅用于教学目的，不作商业用途。
