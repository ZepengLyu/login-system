# ifndef CLIENT_API_H
# define CLIENT_API_H
# include "./client_functions/client_register.h"
# include "./client_functions/client_login.h"
# include "./client_functions/client_query.h"
# include "./client_functions/client_update.h"
# include "./client_functions/client_change_factor.h"

/* 接收用户指令 */
command_t listen_client_command(){
    char *command=OPENSSL_zalloc(COMMAND_MAX_SIZE);
    printf("请输入您要进行的操作，可允许的操作包括 register, login, query, update, change factor\n");
    scanf("%s",command);
    // fgets(command,sizeof(command),stdin);

    command_t command_type=get_command_type(command);
    return command_type;
}

int check_message(const char * buf,size_t buf_size,const char *session_id, const char * user_name,const char wait_type){
    const char _type=buf[0];
    const char * _session_id;
    const char * _user_name;
    const char * _res;
    const char * _data;
    get_with_va(buf,buf_size,4,& _session_id,& _user_name, & _res, & _data);
    
    free(_res);
    free(_data);

    if (memcmp(session_id,_session_id,strlen(session_id))||memcmp(user_name,_user_name,strlen(user_name))||_type!=wait_type){
        return 1;
    }
    else{
        return 0;
    }
}

void client_listen(SSL *ssl,const char *session_id, const char * user_name, const char wait_type, const char ** buf_pp,size_t * buf_size_p){
    char *buf=OPENSSL_zalloc(MESSAGE_BUFFER_MAX_SIZE); //这里得到的 buf 应该是无 '\0' 结尾的
    size_t buf_size;
    while (true){
        usleep(500 * 1000); // 每隔 0.5 秒进行一次读取
        buf_size=SSL_read(ssl,buf,MESSAGE_BUFFER_MAX_SIZE);
        if (check_message(buf,buf_size,session_id,user_name,wait_type)){
            continue;
        }
        else{
            *buf_pp=buf;
            *buf_size_p=buf_size;
            break;
        }
    }
}

/* 用户进行注册 */

int enquire_user_name(char * user_name){ 
    printf("请输入想要注册的用户名\n");
    scanf("%s",user_name);
    return 0;
}

int enquire_email( char * email){

    printf("请输入想要注册的邮箱\n");
    scanf("%s",email);
    return 0;
}
int enquire_email_token(char * email_token){

    printf("请输入邮箱收到的 token\n");
    scanf("%s",email_token);
    return 0;
}



// int client_register(SSL * ssl, const char * session_id){
//     const char * privatekey_file=CLIENT_PRIVATEKEY_FILE;
//     /* 获得用户信息 */
//     // char user_name[USERNAME_MAX_SIZE];
//     printf("请输入想要注册的用户名");
//     const char *user_name="jack";
//     // scanf("%s", &user_name);

//     // char email[EMAIL_MAX_SIZE];
//     const char *email="lyuzepeng.app@gmail.com";
//     printf("请输入想要注册的邮箱");
//     // scanf("%s", &email);

//     /* 发送注册请求 */
//     register_request(ssl, session_id, user_name, email, privatekey_file);

//     /* 等待服务器允许注册回复*/
//     int allowed_res=listen_register_permission_feedback(ssl, session_id, user_name);

//     if (allowed_res==0){  
//         /* user_name 被允许注册 */
//         // 获得 email token
//         char email_token[EMAIL_TOKEN_MAX_SIZE];
//         printf("请输入邮箱收到的 TOKEN");
//         scanf("%s", &email_token);
    
//         register_token_request(ssl, session_id, user_name, email_token);

//         // 等待 server acknowledge register 回复
//         const char * message;
//         int ack_res=listen_register_result_feedback(ssl,session_id,user_name);

//         if (ack_res==0){ //注册成功
//             return 0; 
//         }
//         else{                   // 注册失败
//             printf(message);     // 输出错误信息
//             return 1;       
//         }
//     }
//     else{
//         /* user_name 不被允许注册 */
//         return 1;
//     }
// }

/* 用户进行登陆*/
int client_login(){
    
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

    /* configuration */
    const char * session_id=generate_session_id();
    
    /* user_data*/
    char * user_name=OPENSSL_zalloc(USERNAME_MAX_SIZE+1);
    char * email=OPENSSL_zalloc(EMAIL_MAX_SIZE+1);
    const char *privatekey_file=CLIENT_PRIVATEKEY_FILE;
    
    /* cache */
    const char * buf = OPENSSL_zalloc(MESSAGE_BUFFER_MAX_SIZE+1);
    size_t buf_size;

    const char *token=OPENSSL_zalloc(HEX_TOKEN_SIZE+1);
    const char *email_token=OPENSSL_zalloc(HEX_EMAIL_TOKEN_SIZE+1);
    
    int review_res;

    const char * error_str;

    while (true){
        
        // user command
        command_t command_type=listen_client_command();
        command_type=CMD_REGISTER;
        switch(command_type){
            case CMD_REGISTER:             
                enquire_user_name(user_name);
                enquire_email(email);

                register_request(ssl, session_id, user_name, email, privatekey_file);               
                client_listen(ssl,session_id,user_name,REGISTER_PERMISSION_FEEDBACK,&buf,&buf_size);
                review_res=review_feedback(buf,buf_size,&error_str);
                if (review_res){                            // case 1: error
                    printf("register fails: %s\n",error_str);
                    continue;
                }
                else{
                    enquire_email_token(email_token);
                    register_token_request(ssl, session_id, user_name, email_token);
                    client_listen(ssl,session_id,user_name,REGISTER_RESULT_FEEDBACK,&buf,&buf_size);
                    review_res=review_feedback(buf,buf_size,error_str);
                    if (review_res){                        // case 2: error
                        printf("register fails: %s\n",error_str);
                        continue;
                    }
                    else{                                   // case 3: success
                        printf("register success\n");
                        continue;
                    }
                }    
                break;
            case CMD_LOGIN:
                enquire_user_name(user_name);
                login_request(ssl,session_id,user_name);
                client_listen(ssl,session_id,user_name,CHALLENGE_FEEDBACK,&buf,&buf_size);
                

                // login(ssl,session_id,&token);
                break;
            case CMD_QUERY:
                // client_query(ssl,session_id,token);
                break;
            case CMD_UPDATE:
                // client_update(ssl,session_id,token);
                break;
            case CMD_CHANGE_FACTOR:
                // client_change_factor(ssl,session_id);
                break;
            case CMD_OTHER:
                // fprintf(stderr,"Unrecognized Command");
                break;

        }
    }
}

# endif