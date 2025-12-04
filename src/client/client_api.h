# ifndef CLIENT_API_H
# define CLIENT_API_H
# include "./client_functions/client_register.h"
# include "./client_functions/client_login.h"
# include "./client_functions/client_query.h"
# include "./client_functions/client_update.h"
# include "./client_functions/client_change_factor.h"


command_t listen_client_command(){
    char command[COMMAND_MAX_SIZE];
    printf("请输入您要进行的操作，可允许的操作包括 register, login, query, update, change factor");
    scanf("%d", &command);
    command_t command_type=get_command_type(command);
    return command_type;
}

/* 用户进行注册 */
int client_register(SSL * ssl, const char * session_id){
    const char * privatekey_file=CLIENT_PRIVATEKEY_FILE;

    /* 获得用户信息 */
    // char user_name[USERNAME_MAX_SIZE];
    printf("请输入想要注册的用户名");
    const char *user_name="jack";
    // scanf("%s", &user_name);

    // char email[EMAIL_MAX_SIZE];
    const char *email="lyuzepeng.app@gmail.com";
    printf("请输入想要注册的邮箱");
    // scanf("%s", &email);

    /* 发送注册请求 */
    register_request(ssl, session_id, user_name, email, privatekey_file);

    /* 等待服务器允许注册回复*/
    int allowed_res=listen_register_permission_feedback(ssl, session_id, user_name);

    if (allowed_res==0){  
        /* user_name 被允许注册 */
        // 获得 email token
        char email_token[EMAIL_TOKEN_MAX_SIZE];
        printf("请输入邮箱收到的 TOKEN");
        scanf("%s", &email_token);
    
        register_token_request(ssl, session_id, user_name, email_token);

        // 等待 server acknowledge register 回复
        const char * message;
        int ack_res=listen_register_result_feedback(ssl,session_id,user_name);

        if (ack_res==0){ //注册成功
            return 0; 
        }
        else{                   // 注册失败
            printf(message);     // 输出错误信息
            return 1;       
        }
    }
    else{
        /* user_name 不被允许注册 */
        return 1;
    }
}

/* 用户进行登陆*/
int client_login(SSL * ssl, const char * session_id, const char ** token_pp){

    const char * privatekey_file=CLIENT_PRIVATEKEY_FILE;

    /* 获得用户信息 */
    char user_name[USERNAME_MAX_SIZE];
    printf("请输入想要登陆的用户名");
    scanf("%s", &user_name);

    /* 发送登陆请求 */
    login_request(ssl, session_id, user_name);

    
}

/* 用户进行查询*/
int client_query(SSL * ssl, const char * session_id, const char * token){


}

/* 用户进行更新*/
int client_update(SSL * ssl, const char * session_id, const char * token){
}

/* 用户更改 factor */
int client_change_factor(SSL * ssl, const char * session_id){
}


/* main */
int client_request(SSL *ssl){

    const char * session_id;
    session_id=generate_session_id();
    char * user_name=OPENSSL_zalloc(USERNAME_MAX_SIZE);
    size_t token_size=HEX_TOKEN_SIZE;
    const char *token=OPENSSL_zalloc(token_size+1);

    while (true){
        
        // user command
        command_t command_type=listen_client_command();
        command_type=CMD_REGISTER;
        switch(command_type){
            case CMD_REGISTER:               
                client_register(ssl,session_id);
                break;
            case CMD_LOGIN:
                client_login(ssl,session_id,&token);
                break;
            case CMD_QUERY:
                client_query(ssl,session_id,token);
                break;
            case CMD_UPDATE:
                client_update(ssl,session_id,token);
                break;
            case CMD_CHANGE_FACTOR:
                client_change_factor(ssl,session_id);
                break;
            case CMD_OTHER:
                fprintf(stderr,"Unrecognized Command");
                break;

        }
    }
}

# endif