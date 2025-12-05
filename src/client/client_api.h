# ifndef CLIENT_API_H
# define CLIENT_API_H
# include "./client_functions/client_register.h"
# include "./client_functions/client_login.h"
# include "./client_functions/client_query.h"
# include "./client_functions/client_update.h"
# include "./client_functions/client_change_factor.h"

/* 接收用户指令 */
command_t listen_client_command(const char * prompt){
    char *command=OPENSSL_zalloc(COMMAND_MAX_SIZE+1);
    printf(prompt);
    scanf("%s",command);

    command_t command_type=get_command_type(command);
    return command_type;
}

/* 监听指定的 server 消息 */
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


/* 询问客户输入*/
int enquire_data(const char * prompt,char * data){
    printf(prompt);
    scanf("%s",data);
    return 0;
}


/* 用户进行注册 */
int register_process(SSL *ssl, const char * session_id){
    /* configuration */
    const char *privatekey_file=CLIENT_PRIVATEKEY_FILE;
    char * user_name=malloc(USERNAME_MAX_SIZE+1);
    char * email=OPENSSL_zalloc(EMAIL_MAX_SIZE+1);
    char * email_token= OPENSSL_zalloc(EMAIL_TOKEN_MAX_SIZE+1);
    const char * buf; size_t buf_size;
    int review_res;
    const char * error_str;

    enquire_data("请输入需要注册的 user_name: ",user_name);
    enquire_data("请输入注册邮箱:", email);

    register_request(ssl, session_id, user_name, email, privatekey_file);               
    client_listen(ssl,session_id,user_name,REGISTER_PERMISSION_FEEDBACK,&buf,&buf_size);
    review_res=review_feedback(buf,buf_size,&error_str);
    if (review_res){                            // case 1: error (round 1)
        printf("register fails: %s\n",error_str);
        return 1;
    }
    else{
        enquire_data("请输入邮箱收到的 token:",email_token);
        register_token_request(ssl, session_id, user_name, email_token);
        client_listen(ssl,session_id,user_name,REGISTER_RESULT_FEEDBACK,&buf,&buf_size);
        review_res=review_feedback(buf,buf_size,error_str);
        if (review_res){                        // case 2: error (round 2)
            printf("register fails: %s\n",error_str);
            return 1;
        }
        else{                                   // case 3: success
            printf("register success\n");
            return 0;
        }
    }    
}

/* 用户进行登陆*/
int login_process(SSL *ssl,const char *session_id){
    /* configuration*/
    const char *privatekey_file=CLIENT_PRIVATEKEY_FILE;
    char * user_name=malloc(USERNAME_MAX_SIZE+1);
    char * new_data=malloc(DATA_MAX_SIZE+1);
    const char * buf; size_t buf_size;
    int review_res;
    const char * error_str;
    const char * token;
   

    enquire_data("请输入需要登陆的帐户 user_name",user_name);
    login_request(ssl,session_id,user_name);
    client_listen(ssl,session_id,user_name,CHALLENGE_FEEDBACK,&buf,&buf_size);
    review_res=review_feedback(buf,buf_size,&error_str);
    if (review_res){                            // case 1: login error (round 1)
        printf("login fails: %s\n",error_str);
        return 1;
    }
    else{
        EVP_PKEY * pkey;
        int import_pkey_res=import_privatekey(&pkey,privatekey_file);
        response_challenge(ssl, buf, buf_size, session_id, user_name,pkey);
        client_listen(ssl,session_id,user_name,TOKEN_FEEDBACK,&buf,&buf_size);
        review_res=review_feedback(buf,buf_size,&error_str);
        if (review_res){                            // case 2: login error (round 2)
            printf("login fails: %s\n",error_str);
            return 1;
        }
        else{                                       // case 3: success
            token=get_token(buf,buf_size);
            printf("login success\n");
            int login_status=1;
            while (login_status){
                command_t client_operation=listen_client_command("请输入需要进行的操作，可运行的操作包括 query, upate, change_factor");   // enquire client operation: query, update, quit
                switch (client_operation)
                {   case CMD_QUERY:
                        query_request(ssl,session_id,user_name,token);
                        client_listen(ssl,session_id,user_name,RESULT_FEEDBACK,&buf,&buf_size);
                        review_res=review_feedback(buf,buf_size,&error_str);
                        if (review_res){
                            printf("query fails: %s\n",error_str);
                            continue;
                        }
                        else{
                            printf("query result: %s\n",error_str);
                            continue;
                        }
                        break;

                    case CMD_UPDATE:
                        enquire_data("请输入需要更新的数据",new_data);
                        update_request(ssl,session_id,user_name,new_data,token);
                        client_listen(ssl,session_id,user_name,RESULT_FEEDBACK,&buf,&buf_size);
                        review_res=review_feedback(buf,buf_size,&error_str);
                        if (review_res){
                            printf("update fails: %s\n",error_str);
                            continue;
                        }
                        else{
                            printf("update success\n");
                            continue;
                        }
                        break;

                    // case CMD_QUIT_LOGIN:
                    //     quit_request(ssl,session_id,user_name,new_data,token);
                    //     client_listen(ssl,session_id,user_name,QUIT_FEEDBACK,&buf,&buf_size);
                    //     review_res=review_feedback(buf,buf_size,&error_str);
                    //     if (review_res){
                    //         printf("quit fail: %s\n",error_str);
                    //         continue;
                    //     }
                    //     else{
                    //         printf("quit success\n");
                    //         login_status=0;
                    //         continue;
                    //     }
                    //     break;
                    default:
                        printf("unrecognized command\n");
                        continue;
                }
            }
        }
    }

    
}

/* 用户更改 factor */
int change_factor_process(SSL * ssl, const char * session_id){
    /* configuration */
    char * user_name=malloc(USERNAME_MAX_SIZE+1);
    char * email_token= OPENSSL_zalloc(EMAIL_TOKEN_MAX_SIZE+1);

    const char * buf; size_t buf_size;
    char * error_str;
    int review_res;

    enquire_data("请输入需要更改的帐户的 user_name ",user_name);
    change_factor_request(ssl,session_id,user_name);
    client_listen(ssl,session_id,user_name,CHANGE_FACTOR_FEEDBACK,&buf,&buf_size);
    review_res=review_feedback(buf,buf_size,&error_str);
    if (review_res){                            // case 1: error (round 1)
        printf("change factor fails: %s\n",error_str);
        return 1;
    }
    else{
        enquire_data("请输入邮箱收到的 token",email_token);
        change_factor_token_request(ssl, session_id, user_name, email_token);
        client_listen(ssl,session_id,user_name,CHANGE_FACTOR_TOKEN_FEEDBACK,&buf,&buf_size);
        review_res=review_feedback(buf,buf_size,error_str);
        if (review_res){                        // case 2: error (round 2)
            printf("change factor fails: %s\n",error_str);
            return 1;
        }
        else{                                   // case 3: success
            printf("change factor success\n");
            return 0;
        }
    }    
}


/* main */
int client_request(SSL *ssl){

    /* configuration */
    const char * session_id=generate_session_id();


    while (true){
        
        // user command
        command_t command_type=listen_client_command("请输入您要进行的操作，可允许的操作包括 register, login, change factor\n");
        switch(command_type){
            case CMD_REGISTER:             
                register_process(ssl,session_id);
                break;
            case CMD_LOGIN:
                login_process(ssl,session_id);
                break;
            case CMD_CHANGE_FACTOR:
                change_factor_process(ssl,session_id);
                break;
            case CMD_OTHER:
                fprintf(stderr,"Unrecognized Command");
                int shutdown_res = SSL_shutdown(ssl);
                return 0;
                break;
            

        }
    }
}

# endif