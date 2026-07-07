#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据库初始化脚本
运行后会创建 secure_user.db 并插入两个默认用户。
可以重复运行，不会覆盖已有数据。
"""

import os
import bcrypt
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_user.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # 用户表
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

    # 登录历史表
    c.execute("""
        CREATE TABLE IF NOT EXISTS login_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            ip          TEXT    NOT NULL,
            success     INTEGER NOT NULL,
            timestamp   TEXT    NOT NULL DEFAULT (datetime('now','localtime'))
        )
    """)

    # 默认用户
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
            print(f"  [+] 默认用户 '{uname}' 已创建 (密码: {pwd})")
        else:
            print(f"  [=] 用户 '{uname}' 已存在，跳过")

    conn.commit()
    conn.close()
    print(f"\n数据库初始化完成: {DB_PATH}")


if __name__ == "__main__":
    init_db()
