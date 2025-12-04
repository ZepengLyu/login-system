#ifndef CONFIG_H
#define CONFIG_H

// client interface configuration
# define CLIENT_PRIVATEKEY_FILE "./src/client/pem/client_private_key.pem"

# define COMMAND_MAX_SIZE 100
# define USERNAME_MAX_SIZE 20
# define EMAIL_MAX_SIZE 20

# define MESSAGE_BUFFER_MAX_SIZE 3000


# define C_REGISTER 1
# define C_LOGIN 2
# define C_QUERY 3
# define C_UPDATE 4
# define C_CHANGE_FACTOR 5
# define C_OTHER 6 

typedef enum {
    CMD_REGISTER = C_REGISTER,
    CMD_LOGIN=C_LOGIN,
    CMD_QUERY=C_QUERY,
    CMD_UPDATE=C_UPDATE,
    CMD_CHANGE_FACTOR=C_CHANGE_FACTOR,
    CMD_OTHER=C_OTHER
} command_t;

command_t get_command_type(const char* cmd_str) {
    if (strcmp(cmd_str, "register") == 0) return CMD_REGISTER;
    if (strcmp(cmd_str, "login") == 0) return CMD_LOGIN;
    if (strcmp(cmd_str, "query") == 0) return CMD_QUERY;
    if (strcmp(cmd_str, "update") == 0) return CMD_UPDATE;
    if (strcmp(cmd_str, "change factor") == 0) return CMD_CHANGE_FACTOR;
    return CMD_OTHER;
}

// 这里的 size 都是 uint8 表示下的 size 
# define CHALLENGE_SIZE 32
# define HEX_CHALLENGE_SIZE 64

# define SIGNATURE_SIZE 2420   // ML-DSA 44，128 位安全
# define HEX_SIGNATURE_SIZE 2840   // ML-DSA 44，128 位安全

# define PUBLIC_KEY_SIZE 1312
# define HEX_PUBLIC_KEY_SIZE 2624

# define BUFFER_MAX_SIZE 3000

# define TOKEN_SIZE 32 
# define HEX_TOKEN_SIZE 64 

# define CHANGE_FACTOR_TOKEN_SIZE 8 //出于用户体验，一般不会设置得太大
# define HEX_CHANGE_FACTOR_TOKEN_SIZE 16 //出于用户体验，一般不会设置得太大

# define SESSION_ID_SIZE 16  
# define HEX_SESSION_ID_SIZE 32  


// database config
#define HOST "localhost" 
#define USERNAME "login_system_admin" 
#define PASSWORD "123456" 
#define DATABASE "login_system"

#define TAB_USER_DATA "user_data"
#define TAB_SESSION "session"
#define TAB_REGISTER_SESSION "register_session"

#define SQL_MAX_LEN 200
#define DB_BUFFER_MAX_SIZE 20000
#define DATETIME_SIZE 20


#endif 