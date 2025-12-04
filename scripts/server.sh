#!/bin/zsh

# 默认参数
DEFAULT_PORT=4443
DEFAULT_CHAIN="./src/server/pem/chain.pem"
DEFAULT_KEY="./src/server/pem/server_key.pem"

# 使用参数或默认值
PORT=${1:-$DEFAULT_PORT}
CHAIN_PEM=${2:-$DEFAULT_CHAIN}
SERVER_KEY=${3:-$DEFAULT_KEY}

# 启动服务器
./bin/SIT_server $PORT "$CHAIN_PEM" "$SERVER_KEY"