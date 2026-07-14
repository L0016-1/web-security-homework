from flask import Flask, render_template, request, redirect, session, send_from_directory, url_for
import sqlite3, os, sys

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

UPLOAD_DIR = os.path.join(app.root_path, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}


def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
    """)
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('admin', 'admin123', 'admin@example.com', '13800138000', 99999)")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES ('alice', 'alice2025', 'alice@example.com', '13900139001', 100)")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    user = None
    msg = request.args.get("msg", "")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user = USERS[username]
            return render_template("index.html", user=user)
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error, msg=msg)


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] {sql}", flush=True)
        try:
            c.execute(sql)
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except sqlite3.IntegrityError:
            error = "用户名已存在"
        conn.close()
    return render_template("register.html", error=error)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    results = []
    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    if keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        rows = c.fetchall()
        conn.close()
        for row in rows:
            results.append({"id": row[0], "username": row[1], "email": row[2], "phone": row[3]})
    return render_template("index.html", user=user, search_keyword=keyword, search_results=results)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")
    user = USERS.get(username)

    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or file.filename == "":
            return render_template("upload.html", user=user, error="请选择要上传的文件")
        filename = file.filename
        filepath = os.path.join(UPLOAD_DIR, filename)
        file.save(filepath)
        file_url = "/static/uploads/" + filename
        return render_template("upload.html", user=user, file_url=file_url, filename=filename)

    return render_template("upload.html", user=user)


@app.route("/profile")
def profile():
    user_id = request.args.get("user_id", "")
    profile_data = None
    if user_id:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"SELECT id, username, email, phone, balance FROM users WHERE id = {user_id}"
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        row = c.fetchone()
        conn.close()
        if row:
            profile_data = {"id": row[0], "username": row[1], "email": row[2], "phone": row[3], "balance": row[4]}
    return render_template("profile.html", profile_data=profile_data)


@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id", "")
    amount = request.form.get("amount", "0")
    if user_id:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"UPDATE users SET balance = balance + {amount} WHERE id = {user_id}"
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        conn.commit()
        conn.close()
    return redirect(f"/profile?user_id={user_id}")


@app.route("/change-password", methods=["POST"])
def change_password():
    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    if username and new_password:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()
        sql = f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'"
        print(f"[SQL] {sql}", flush=True)
        c.execute(sql)
        conn.commit()
        conn.close()
        # 同步更新内存中的密码
        if username in USERS:
            USERS[username]["password"] = new_password
    return redirect("/profile")


@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None
    if name:
        filepath = os.path.join("pages", name)
        if os.path.isfile(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                page_content = f.read()
        else:
            filepath_html = os.path.join("pages", name + ".html")
            if os.path.isfile(filepath_html):
                with open(filepath_html, "r", encoding="utf-8") as f:
                    page_content = f.read()
            else:
                page_content = "页面不存在"

    username = session.get("username")
    user = None
    if username and username in USERS:
        user = USERS[username]
    return render_template("index.html", user=user, page_content=page_content)


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
