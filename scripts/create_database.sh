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



# build the table register_session
TB_REGISTER_SESSION_TABLE="register_session"
register_session_sql="DROP TABLE IF EXISTS $TB_REGISTER_SESSION_TABLE; CREATE TABLE IF NOT EXISTS $TB_REGISTER_SESSION_TABLE (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id CHAR(32) NOT NULL UNIQUE,
    user_name TEXT NOT NULL,
    email TEXT NOT NULL,
    public_key TEXT NOT NULL,
    email_token_timestamp DATETIME NOT NULL,
    email_token TEXT NOT NULL
);"

echo "please input the password of '$LOGIN_SYSTEM_ADMIN'@'localhost' "
if mysql -u $LOGIN_SYSTEM_ADMIN $DB_NAME -e $register_session_sql -p ; then
    echo "Success: Create the table '$TB_REGISTER_SESSION_TABLE' successfully\n"
else
    echo "Error: fail to the table '$TB_REGISTER_SESSION_TABLE'\n "
fi


# build the table session
TB_SESSION_TABLE="session"

session_sql="DROP TABLE IF EXISTS $TB_SESSION_TABLE;CREATE TABLE IF NOT EXISTS $TB_SESSION_TABLE (
    id INT AUTO_INCREMENT PRIMARY KEY,
    session_id CHAR(32) NOT NULL UNIQUE,
    user_name TEXT NOT NULL ,
    login_request_timestamp DATETIME NOT NULL ,
    challenge TEXT NULL,
    response TEXT NULL,
    response_timestamp DATETIME NULL ,
    token TEXT NULL,
    token_timestamp DATETIME NULL ,
    change_factor_token TEXT NULL
);"

echo "please input the password of '$LOGIN_SYSTEM_ADMIN'@'localhost' "
if mysql -u $LOGIN_SYSTEM_ADMIN $DB_NAME -e $session_sql -p ; then
    echo "Success: Create the table '$TB_SESSION_TABLE' successfully\n"
else
    echo "Error: fail to the table '$TB_SESSION_TABLE'\n "
fi
