#!/bin/zsh

# 默认参数
DEFAULT_HOSTNAME="localhost"
DEFAULT_PORT="4443"
DEFAULT_PEM_FOLDER="./src/client/pem/"

# 使用参数或默认值
HOSTNAME=${1:-$DEFAULT_HOSTNAME}
PORT=${2:-$DEFAULT_PORT}
PEM_FOLDER=${3:-$DEFAULT_PEM_FOLDER}

# 启动client 
./bin/client $HOSTNAME "$PORT" "$PEM_FOLDER"

