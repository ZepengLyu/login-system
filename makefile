# Compiler
CC = /usr/bin/clang

# Common flags
CFLAGS = -w -fcolor-diagnostics -fansi-escape-codes -g
LDFLAGS = -lssl -lcrypto

# Directories
SRC_DIR = src
TEST_DIR = test
BIN_DIR = bin

# Targets
all: test functions_test server client openssl_tls_client openssl_tls_server

test: $(TEST_DIR)/test.c
    $(CC) $(CFLAGS) $< -o $(BIN_DIR)/test `pkg-config --cflags --libs mysqlclient` `pkg-config --cflags --libs openssl` `pkg-config --cflags --libs libcurl`

functions_test: $(TEST_DIR)/functions_test.c
    $(CC) $(CFLAGS) $< -o $(TEST_DIR)/functions_test `pkg-config --cflags --libs mysqlclient` `pkg-config --cflags --libs openssl` `pkg-config --cflags --libs libcurl`

server: $(SRC_DIR)/server/server.c
    $(CC) $(CFLAGS) $< -o $(BIN_DIR)/server $(LDFLAGS)

client: $(SRC_DIR)/client/client.c
    $(CC) $(CFLAGS) $< -o $(BIN_DIR)/client $(LDFLAGS)

openssl_tls_client: $(SRC_DIR)/client/openssl_tls_client.c
    $(CC) $(CFLAGS) $< -o $(SRC_DIR)/client/openssl_tls_client $(LDFLAGS)

openssl_tls_server: $(SRC_DIR)/server/openssl_tls_server.c
    $(CC) $(CFLAGS) $< -o $(SRC_DIR)/server/openssl_tls_server $(LDFLAGS)

# Clean up build artifacts
clean:
    rm -f $(BIN_DIR)/* $(TEST_DIR)/functions_test $(SRC_DIR)/client/openssl_tls_client $(SRC_DIR)/server/openssl_tls_server