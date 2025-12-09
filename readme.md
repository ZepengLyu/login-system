# Introduction

Login protocol 为 Dilithium-based Challenge-Response protocol.

证书使用 ML-DSA-44 证书。Key exchange 算法则使用后量子混合算法 X25519mlkem768,



# Preliminaries 

## MYSQL 
server 使用的是 MySQL 数据库，需保证您的电脑已经安装

### 为 root 设置密码 (由 homebrew 安装的 mysql，默认无密码)
ROOT_USER="root"
ROOT_PASS="123456"
mysqladmin -u $ROOT_USER password $ROOT_PASS 

## OpenSSL
使用的 OpenSSL 版本为 3.5，需保证您的电脑已经安装

# Running
## 建立数据库
运行 create_database.sh 文件 




# limitations
1. 目前服务器端未进行多线程开发
2. 目前采用的是自定义应用层协议，预计在未来使用更通用的 http 协议
3. 未进行 fuzz 测试
4. 错误处理和内存协议还未进行完善
5. session_id 目前由 client 生成，这并不符合通用做法。未来的版本将会由 server 生成，实际上，可以直接使用 session_id 作为 challenge 以减少通信量。
6. 目前的证书仅使用 ML-DSA-44 签名，更好的方式应该是像 key exchange 算法 (X25519mlkem768) 那样使用混合算法。一种实现的方法是使用混合证书链。
