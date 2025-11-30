#!/usr/bin/env zsh
# 为 ca, client 和 server 生成密码学材料

cd ../pem

rm -rf ./client
rm -rf ./server
rm -rf ./ca

mkdir ./client
mkdir ./server
mkdir ./ca

# ca 
ca_key_file="./ca/ca_key.pem"
ca_pubkey_file="./ca/ca_pubkey.pem"

ca_identity="/C=CN/ST=HongKong/L=Kowloon/O=login_system_comp/OU=dev/CN=root_ca"
ca_cert_file="./ca/ca_certificate.pem"

# server
server_key_file="./server/server_key.pem"
server_pubkey_file="./server/server_pubkey.pem"

server_identity="/C=CN/ST=HongKong/L=Kowloon/O=login_system_comp/OU=dev/CN=localhost"
server_req_file="./server/server_req.pem"
server_cert_file="./server/server_certificate.pem"

chain_file="./server/chain.pem"

ext_file="./config/openssl.cnf"


# Create ca key
openssl genpkey -algorithm mldsa87 \
-out $ca_key_file -outform PEM -outpubkey $ca_pubkey_file \
&& echo "==> Create ca key Successfully" \
|| echo "==> fail to create ca key"

# Create ca self-certificate (use x509 command)
openssl x509 -new -key $ca_key_file \
-out $ca_cert_file \
-subj $ca_identity -days 360 \
-extfile $ext_file -extensions v3_ca \
&& echo "==> Create ca self-certificate Successfully" \
|| echo "==> fail to ca self-certificate"


# Copy ca certificate to server and Client
cp $ca_cert_file "./server"
cp $ca_cert_file "./client"



# Create server key
openssl genpkey -algorithm mldsa87 \
-out $server_key_file -outform PEM \
-outpubkey $server_pubkey_file \
&& echo "==> Create server key Successfully" \
|| echo "==> fail to server key"

# Create server crl
# csr 方式获得 cert 申请
# 在这一步只有 config 文件而没有 extfile 文件
openssl req -new -key $server_key_file -out $server_req_file -subj $server_identity \
&& echo "==> Create server crl Successfully" \
|| echo "==> fail to Create server crl"

# Create server certificate (在这一步有 extfile)
openssl x509 -req -in $server_req_file -CA $ca_cert_file -CAkey $ca_key_file \
-out $server_cert_file -extfile $ext_file -extensions v3_req  -CAcreateserial \
&& echo "==> the server certificate is signed by ca successfully" \
|| echo "==> fail to create server certificate"


# Verify server certificate using ca certificate:
openssl verify -CAfile  $ca_cert_file    $server_cert_file \
&& echo "==> Verify server certificate using ca certificate successfully" \
|| echo "==> fail to Verify server certificate"


# Create chain file 
cat $server_cert_file $ca_cert_file > $chain_file \
&& echo "==> Create chain file successfully" \
|| echo "==> fail to create chain file"



# 将 pem 文件复制到 src/client/pem 和 src/server/pem 中
cp ./server/*  ../src/server/pem/  
cp ./client/*  ../src/client/pem/  

