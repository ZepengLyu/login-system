# Preliminaries 

# MYSQL 
server 使用的是 MySQL 数据库，需保证您的电脑已经安装

## 为 root 设置密码 (由 homebrew 安装的 mysql，默认无密码)
ROOT_USER="root"
ROOT_PASS="123456"
mysqladmin -u $ROOT_USER password $ROOT_PASS 

## 运行 create_database.sh 文件

# 使用的 Openssl Curl 库位于



# limitations
此项目暂时未设计服务器多线程运行，同时，也没有进行 fuzz 测试。这些功能预计在未来进行开发

Key exchange 算法则使用后量子混合算法 X25519mlkem768,

证书使用 ML-DSA-44 证书
