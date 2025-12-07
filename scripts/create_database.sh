#!/bin/zsh

LOGIN_SYSTEM_ADMIN="login_system_admin"
DB_NAME="login_system"



# build the table user_data
TB_USER_DATA="user_data"
user_data_sql="DROP TABLE IF EXISTS $TB_USER_DATA;CREATE TABLE IF NOT EXISTS $TB_USER_DATA (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name VARCHAR(20) NOT NULL UNIQUE,
    email TEXT NOT NULL, 
    public_key TEXT NOT NULL,
    info VARCHAR(100) CHARACTER SET utf8 NULL DEFAULT ''
);"

echo "please input the password of '$LOGIN_SYSTEM_ADMIN'@'localhost' "
if mysql -u $LOGIN_SYSTEM_ADMIN $DB_NAME -e $user_data_sql -p ; then
    echo "Success: Create the table '$TB_USER_DATA' successfully\n"
else
    echo "Error: fail to the table '$TB_USER_DATA'\n "
fi



# build the table session
TB_SESSION_TABLE="session"

session_sql="DROP TABLE IF EXISTS $TB_SESSION_TABLE;CREATE TABLE IF NOT EXISTS $TB_SESSION_TABLE (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_name TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    session_id CHAR(32) NOT NULL,
    session_type TEXT NOT NULL,
    challenge TEXT,
    response TEXT,
    token TEXT,
    email TEXT ,
    public_key TEXT,
    email_token TEXT
);"

echo "please input the password of '$LOGIN_SYSTEM_ADMIN'@'localhost' "
if mysql -u $LOGIN_SYSTEM_ADMIN $DB_NAME -e $session_sql -p ; then
    echo "Success: Create the table '$TB_SESSION_TABLE' successfully\n"
else
    echo "Error: fail to the table '$TB_SESSION_TABLE'\n "
fi
