#!/bin/zsh

# 配置变量

ROOT_USER="root"
ROOT_PASS="123456"
DB_NAME="login_system"
DB_SESSION_SIZE="32"


# # 为 root 设置密码 (由 homebrew 安装的 mysql，默认无密码)
# mysqladmin -u $ROOT_USER password $ROOT_PASS 

# 建立数据库
sql="CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET ascii;"
mysql -u $ROOT_USER -p$ROOT_PASS -e $sql

# 建立 user_data 表 1959*8=15672
sql="CREATE TABLE IF NOT EXISTS user_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(20) NOT NULL UNIQUE,
    email TEXT NOT NULL,
    public_key TEXT NOT NULL,
    info VARCHAR(100) CHARACTER SET utf8 NULL DEFAULT ""
);"

mysql -u $ROOT_USER -p$ROOT_PASS  $DB_NAME -e $sql

# 建立 register_session_data 
sql="CREATE TABLE IF NOT EXISTS register_session_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id CHAR($DB_SESSION_SIZE) NOT NULL UNIQUE,
    user_name TEXT NOT NULL,
    email VARCHAR(50) NOT NULL,
    email_token_timestamp DATETIME NOT NULL,
    email_token TEXT NOT NULL
);"

mysql -u $ROOT_USER -p$ROOT_PASS  $DB_NAME -e $sql

# 建立 session_data 表 3309*8=26472

sql="CREATE TABLE IF NOT EXISTS session_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id CHAR($DB_SESSION_SIZE) NOT NULL UNIQUE,
    user_name TEXT NOT NULL ,
    login_request_timestamp DATETIME NOT NULL ,
    challenge TEXT NULL,
    response TEXT NULL,
    response_timestamp DATETIME NULL ,
    token TEXT NULL,
    token_timestamp DATETIME NULL ,
    change_factor_token TEXT NULL
);"

mysql -u $ROOT_USER -p$ROOT_PASS  $DB_NAME -e $sql