
# 建立 login system admin 用户
echo "Create login system admin..."

ROOT_USER="root"
DB_NAME="login_system"

# build the database
build_database_sql="CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET ascii;"

echo "please input the password of '$ROOT_USER'@'localhost' "
if mysql -u $ROOT_USER -e $build_database_sql -p; then
    echo "Success: create the database '$DB_NAME' successfully"
else
    echo "Error: fail to create the database '$DB_NAME' "
fi

# create the admin user 
LOGIN_SYSTEM_ADMIN="login_system_admin"
LOGIN_SYSTEM_ADMIN_PW="123456"
vared -p "please design the password of '$LOGIN_SYSTEM_ADMIN':" -c LOGIN_SYSTEM_ADMIN_PW

create_admin_ssql="CREATE USER '${LOGIN_SYSTEM_ADMIN}'@'localhost' IDENTIFIED BY '$LOGIN_SYSTEM_ADMIN_PW' ";

echo "please input the password of '$ROOT_USER'@'localhost' "
if mysql -u $ROOT_USER  -e $create_admin_ssql -p; then
    echo "Success: create the user '$LOGIN_SYSTEM_ADMIN' successfully"
else
    echo "Error: fail to create the user '$LOGIN_SYSTEM_ADMIN' "
fi

# grant the privilege to the admin
grant_sql="grant all on $DB_NAME.* to '$LOGIN_SYSTEM_ADMIN'@'localhost'"

echo "please input the password of '$ROOT_USER'@'localhost' "
if mysql -u $ROOT_USER  -e $grant_sql -p; then
    echo "Success: grant the privileges to '$LOGIN_SYSTEM_ADMIN' successfully"
else
    echo "Error: fail to grant the privileges to '$LOGIN_SYSTEM_ADMIN'"
fi