#ifndef CONFIG_H
#define CONFIG_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <string.h>

// SSL type
# define CHALLENGE_SIZE 32
# define SIGNATURE_SIZE 2420   // ML-DSA 44，128 位安全
# define PUBLIC_KEY_SIZE 1312
# define BUFFER_MAX_SIZE 3000 
# define TOKEN_SIZE 32
# define CHANGE_FACTOR_TOKEN_SIZE 8
# define SESSION_ID_SIZE 16




// database config
#define HOST "localhost" 
#define USERNAME "root" 
#define PASSWORD "123456" 
#define DATABASE "login_system" 
#define TAB_USER_DATA "user_data"
#define TAB_SESSION "session_data"
#define TAB_REGISTER_SESSION "register_session_data"
#define SQL_MAX_LEN 200

#define DB_BUFFER_MAX_SIZE 20000
#define DATETIME_SIZE 20


#endif 