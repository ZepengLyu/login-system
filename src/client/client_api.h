# ifndef CLIENT_API_H
# define CLIENT_API_H
# include "./client_functions.h"


int register_request(SSL * ssl, 
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const char *email,size_t email_size,
    const char * privatekey_file){   
    
    const unsigned char *pubkey; size_t pubkey_size;
    generate_keypair(&pubkey,&pubkey_size,privatekey_file);     

    register_request_t * register_request=create_register_request(session_id, session_id_size,
        user_name, username_size, email, email_size, pubkey, pubkey_size);

    const unsigned char * message; size_t message_size;
    create_register_request_message(&message,&message_size,register_request);

    SSL_write(ssl,message,message_size);

    return 0;
}




int login_request(SSL *ssl, const unsigned char * session_id, size_t session_id_size,
    const char * user_name,size_t username_size)
{   
    login_request_t * login_request=create_login_request(session_id, session_id_size,
        user_name,username_size);

    const unsigned char * message; size_t message_size;
    create_login_request_message(&message,&message_size,login_request);

    SSL_write(ssl,message,message_size);
    return 0;
}



int response_challenge(SSL * ssl, 
    const unsigned char * session_id, size_t session_id_size, const char * user_name,size_t username_size,
    const unsigned char * buf, size_t buf_size, EVP_PKEY * pkey)
{
    
    // parse challenge_text
    challenge_feedback_t * challenge_feedback=parse_challenge_feedback(buf,buf_size);
    
    int check_res=check_challenge_feedback(challenge_feedback, session_id, session_id_size, user_name, username_size);
    
    if (check_res!=0){
        fprintf(stderr,"challenge feedback check fails");
        return 1;
    }
    // sign challenge
    const unsigned char * signature;    size_t signature_size;
    sign_message(challenge_feedback->challenge, challenge_feedback->challenge_size, &signature, &signature_size, pkey);
    
    // get response_request
    response_request_t * response_request=create_response_request(challenge_feedback,signature,signature_size);

    // get response_text
    unsigned char * message;    size_t message_size;
    create_response_request_message(&message, &message_size, response_request);
    
    SSL_write(ssl,message,message_size);

    return 0;
}


int get_token(const unsigned char * buf, size_t buf_size,
    const unsigned char ** token_pp, size_t * token_size_p,
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size){

    token_feedback_t * token_feedback = parse_token_feedback(buf, buf_size);

    int check_res=check_token(token_feedback, session_id, session_id_size, user_name, username_size);
    if (check_res!=0){
        fprintf(stderr,"token feedback check fails");

        return 1;
    }

    *token_pp=token_feedback->token;
    *token_size_p=token_feedback->token_size;

    return 0;
}


int update_request(SSL *ssl, 
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, 
    const char * data,
    const unsigned char * token, size_t token_size){

    update_request_t * update_request=create_update_request(session_id,session_id_size,
        user_name,strlen(user_name),data,strlen(data),
        token,token_size);    

    const unsigned char * message;    size_t message_size;
    create_update_request_message(&message,&message_size,update_request);

    SSL_write(ssl,message,message_size);
}

int query_request(SSL *ssl, 
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, 
    const unsigned char * token, size_t token_size){

    query_request_t * update_request=create_query_request(session_id,session_id_size,
        user_name,strlen(user_name),
        token,token_size);    

    const unsigned char * message;    size_t message_size;
    create_query_request_message(&message,&message_size,update_request);

    SSL_write(ssl,message,message_size);
}


int change_factor_request(SSL * ssl,
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size){

    change_factor_request_t * change_factor_request=create_change_factor_request(
        session_id, session_id_size,
        user_name, username_size
    );

    const unsigned char * message; size_t message_size;
    create_change_factor_request_message(&message,&message_size,change_factor_request);

    SSL_write(ssl,message,message_size);
    return 0;
}


int change_factor_token_request(SSL * ssl,
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const unsigned char * new_pubkey, size_t new_pubkey_size,
    const unsigned char * token, size_t token_size){

    change_factor_token_request_t * change_factor_token_request=create_change_factor_token_request(
        session_id, session_id_size,
        user_name, username_size,
        new_pubkey,new_pubkey_size,
        token, token_size);     

    const unsigned char * message; size_t message_size;
    create_change_factor_token_request_message(&message,&message_size,change_factor_token_request);
    SSL_write(ssl,message,message_size);
    return 0;

}

// print feedback
int print_feedback(const unsigned char * buf,size_t buf_size){
    general_feedback_t * feedback_data={0};
    get_with_va(buf,buf_size,3,
        &feedback_data->session_id, &feedback_data->session_id_size,
        &feedback_data->user_name, &feedback_data->username_size,
        &feedback_data->message, &feedback_data->message_size
    );
    append_character(feedback_data->message,feedback_data->message_size,'\0');
    fprintf(stderr,"%s",feedback_data->message);
    return 0;
}

 
int client_listen(SSL * ssl,const char * user_name, size_t user_name_size, char * pkey_file){

    unsigned char buf[BUFFER_MAX_SIZE];
    size_t buf_size; //real buffer size
   
    // import pkey
    FILE* fp=fopen(pkey_file,"r");
    EVP_PKEY * pkey;
    import_privatekey(&pkey,fp);


    // session id
    const unsigned char * session_id=generate_session_id();
    size_t session_id_size=SESSION_ID_SIZE;

    // token
    const unsigned char * token;
    size_t token_size=TOKEN_SIZE;


    while (SSL_read(ssl,buf,buf_size)>0 ){
        
        unsigned char message_type=buf[0];
        
        switch(message_type){
            case CHALLENGE_TYPE:
                response_challenge(ssl,
                session_id,session_id_size,
                user_name,user_name_size,    
                (const unsigned char *)buf,buf_size,pkey);
                break;
            case FEEDBACK_TYPE:
                print_feedback((const unsigned char *)buf,buf_size);
                break;
            case TOKEN_TYPE:   
                get_token(buf,buf_size,
                    &token,&token_size,
                    session_id,session_id_size,
                    user_name,user_name_size);
                break;
            default:
                fprintf(stderr,"unknown message type");
                break;
        }

    }
    return 0;
}
# endif