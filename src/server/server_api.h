# include "./server_functions.h"


int feedback_to_client(SSL * ssl,
    const unsigned char * session_id, size_t session_id_size, 
    const char *user_name, size_t user_name_size, 
    const char * message_content, size_t message_content_size){
    
    general_feedback_t * general_feedback=create_general_feedback(session_id,session_id_size,user_name,user_name_size,message_content,message_content_size);

    const unsigned char * message;    size_t message_size;
    create_general_feedback_message(&message,&message_size,general_feedback);
    
    SSL_write(ssl,message,message_size);
    return 0;
}



int register_callback(SSL * ssl, MYSQL* my_connection, unsigned char * buf, size_t buf_size){
   
    register_request_t *register_request=parse_register_request(buf, buf_size);
    
    record_register(my_connection,
        register_request->user_name,register_request->username_size,
        register_request->email,register_request->email_size,
        register_request->pubkey,register_request->pubkey_size
    );

    return 0;
}



int response_callback(SSL * ssl, MYSQL * my_connection, unsigned char * buf, size_t buf_size){
    
    // parse response
    response_request_t * response_request=parse_response_request(buf, buf_size);

    // query challenge
    const unsigned char * challenge; size_t challenge_len;
    query_challenge(my_connection, 
        response_request->session_id,response_request->session_id_size,
        response_request->user_name,response_request->username_size,
        &challenge, &challenge_len);
       
    // query public key
    EVP_PKEY * pubkey={0};
    query_pubkey(my_connection, 
        response_request->user_name, response_request->username_size,
        &pubkey);

    // validate response 
    if (challenge){
        int res= validate_signature(challenge, challenge_len, response_request->response, response_request->response_size, pubkey);
        if (res==0){
            token_feedback_t * token_feedback=create_token_feedback(response_request);
            const unsigned char * token_message; size_t token_message_size;
            create_token_feedback_message(&token_message, &token_message_size, token_feedback);
            SSL_write(ssl,token_message,token_message_size);
            record_token(my_connection, 
                token_feedback->session_id,token_feedback->session_id_size,
                token_feedback->user_name,token_feedback->username_size,
                token_feedback->token,token_feedback->token_size
                );
        }
        else{
            general_feedback_t * general_feedback=create_general_feedback(response_request->session_id,response_request->session_id_size,
                response_request->user_name,response_request->username_size,"invalid response text",strlen("invalid response text"));
            
                const unsigned char * feedback_message; size_t feedback_message_size;
            create_general_feedback_message(&feedback_message,&feedback_message_size,general_feedback);

            SSL_write(ssl,feedback_message,feedback_message_size);
        }
    }
    return 0;
}


int update_request_callback(SSL *ssl, MYSQL * my_connection,
    const unsigned char * buf, size_t buf_size){

    update_request_t * update_request=parse_update_request(buf,buf_size);

    int res=validate_token(my_connection,
        update_request->session_id,update_request->session_id_size,
        update_request->user_name,update_request->username_size,
        update_request->token,update_request->token_size);
    
    if (res){
        update_data(my_connection,
            update_request->user_name,update_request->username_size,
            update_request->data,update_request->data_size
        );
    }
    else{
        feedback_to_client(ssl,
            update_request->session_id,update_request->session_id_size,
            update_request->user_name,update_request->username_size,
            "invalid token",strlen("invalid token"));
    }
}


int query_request_callback(SSL *ssl,MYSQL * my_connection,
    const unsigned char * buf, size_t buf_size){
    
    query_request_t * query_request = parse_query_request(buf,buf_size);

    int res=validate_token(my_connection,
        query_request->session_id, query_request->session_id_size,
        query_request->user_name, query_request->username_size,
        query_request->token, query_request->token_size);
    if (res){
        const char * data; size_t data_size;
        query_data(my_connection,query_request->user_name,query_request->username_size,&data,&data_size);
        feedback_to_client(ssl,
            query_request->session_id,query_request->session_id_size,
            query_request->user_name,query_request->username_size,
            data,data_size);
    }
    else{
        feedback_to_client(ssl,
            query_request->session_id,query_request->session_id_size,
            query_request->user_name,query_request->username_size,
            "invalid token",strlen("invalid token"));
    }
}


int change_factor_request_callback(SSL *ssl, MYSQL * my_connection, const unsigned char * buf, size_t buf_size){
  
    change_factor_request_t * change_factor_request= parse_change_factor_request(buf,buf_size);
   
    // query email as the recipient
    const char * email; size_t email_size;
    query_email(my_connection, 
        change_factor_request->user_name, change_factor_request->username_size,
        &email, &email_size);

    // generate change-factor token
    const unsigned char * change_factor_token = generate_token();
    size_t token_size=TOKEN_SIZE;

    // record change-factor token into database
    record_change_factor_token(my_connection,
        change_factor_request->session_id,change_factor_request->session_id_size,
        change_factor_request->user_name,change_factor_request->username_size,
        change_factor_token, token_size);

    // send email to user
    // send_email(email, change_factor_token, token_size);
       
    feedback_to_client(ssl,
        change_factor_request->session_id, change_factor_request->session_id_size,
        change_factor_request->user_name, change_factor_request->username_size,
        "send token to the account register email", strlen("send token to the account register email"));

        
    return 0;

}


int change_factor_token_request_callback(SSL *ssl, MYSQL * my_connection, const unsigned char * buf, size_t buf_size){
    
    change_factor_token_request_t * change_factor_token_request = parse_change_factor_token_request(buf,buf_size);

    int res=validate_change_factor_token(my_connection,
        change_factor_token_request->session_id, change_factor_token_request->session_id_size,
        change_factor_token_request->user_name, change_factor_token_request->username_size,
        change_factor_token_request->token, change_factor_token_request->token_size);
    
    if (res){
        update_pubkey(my_connection,
            change_factor_token_request->user_name,change_factor_token_request->username_size,
            change_factor_token_request->new_pubkey,change_factor_token_request->new_pubkey_size
            );
        
        feedback_to_client(ssl,
            change_factor_token_request->session_id, change_factor_token_request->session_id_size,
            change_factor_token_request->user_name, change_factor_token_request->username_size,
            "change factor token sucessfully",strlen("change factor token sucessfully"));
    }
    else{
        feedback_to_client(ssl,
            change_factor_token_request->session_id, change_factor_token_request->session_id_size,
            change_factor_token_request->user_name, change_factor_token_request->username_size,
            "invalid change factor token",strlen("invalid change factor token"));
    }

    return 0;
}



int server_listen (SSL * ssl,const char * pkey_file){

    unsigned char buf[BUFFER_MAX_SIZE];
    size_t buf_size;    //real buffer size    

    MYSQL my_connection;
    mysql_init(&my_connection);
    if (!mysql_real_connect(&my_connection, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, CLIENT_FOUND_ROWS)) {
        printf("fail to connect to database");
        return 1;
    }

    EVP_PKEY *pubkey;
    FILE* fp=fopen(pkey_file,"r");
    pubkey=PEM_read_PUBKEY(fp,NULL,NULL,NULL);


    while (SSL_read(ssl,buf,buf_size)>0 ){

        unsigned char message_type=buf[0];

        switch(message_type){
            case REGISTER_TYPE:
                register_callback(ssl,&my_connection,buf,buf_size);
                break;
            case LOGIN_TYPE:
                login_callback(ssl,&my_connection,buf,buf_size);
                break;
            case RESPONSE_TYPE:
                response_callback(ssl,&my_connection,buf,buf_size);
            // case DATA_OPERATION_TYPE:
            //     // call_bankend()
            //      break;
            // default:
            //  break;
        }
    }
    return 0;
}
