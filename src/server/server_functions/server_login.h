# ifndef SERVER_LOGIN_H
# define SERVER_LOGIN_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "./server_database.h"
#include "../../config.h"
#include "../../common.h"
#include "../../message_type.h"
#include "../../crypto.h"


/* login request */
login_request_t * parse_login_request(const char *buf, size_t buf_size){

    login_request_t * login_request =_create_request(sizeof(login_request_t));
    get_with_va(buf, buf_size, 2, 
        &login_request->session_id, 
        &login_request->user_name);

    return login_request;
}

challenge_feedback_t * create_challenge_feedback(login_request_t * request_data,const char *res, const char * challenge){

    challenge_feedback_t * challenge_feedback=_create_feedback(sizeof(challenge_feedback_t));
    
    challenge_feedback->session_id=request_data->session_id;
    challenge_feedback->user_name=request_data->user_name;
    challenge_feedback->res=res;
    challenge_feedback->challenge=challenge;

    return challenge_feedback;
}

const char * create_challenge_feedback_message(challenge_feedback_t * feedback_data){
    const char * message;
    message= fill_with_va(CHALLENGE_FEEDBACK,4,
        feedback_data->session_id,
        feedback_data->user_name,
        feedback_data->res,
        feedback_data->challenge
    );
    return message;
}

int _login_request_callback(MYSQL* my_connection, const char * buf, size_t buf_size,const char ** message_pp){
   
    // parse login request message
    login_request_t * request_data=parse_login_request(buf, buf_size);
    
    // generate challenge
    const char * challenge=generate_challenge();
    
    // record challenge feedback
    int database_res=record_login(my_connection, 
        request_data->session_id,
        request_data->user_name,
        challenge
    );

    if (database_res==0){       
        challenge_feedback_t * challenge_feedback=create_challenge_feedback(request_data,"0",challenge);
    
        *message_pp=create_challenge_feedback_message(challenge_feedback);
    }
    else {
        challenge_feedback_t * challenge_feedback=create_challenge_feedback(request_data,"1","");
    
       * message_pp=create_challenge_feedback_message(challenge_feedback);
    }
        
    return 0;
}

int login_request_callback(SSL * ssl, MYSQL* my_connection, const char * buf, size_t buf_size){
    const char * message;
    int res=_login_request_callback(my_connection,buf,buf_size,&message);
    SSL_read(ssl,message,strlen(message)+1);
    return res;
}


/* response request */
response_request_t* parse_response_request(const char * buf, size_t buf_size){
    
    response_request_t * response_request=_create_request(sizeof(response_request_t));

    get_with_va(buf,buf_size,3,&response_request->session_id, &response_request->user_name, &response_request->response);
    return response_request;
}

token_feedback_t * create_token_feedback( response_request_t * request_data, const char * res, const char * token){

    token_feedback_t * token_feedback=_create_feedback(sizeof(token_feedback_t));

    token_feedback->session_id=request_data->session_id;
    token_feedback->user_name=request_data->user_name;
    token_feedback->res=res;
    token_feedback->token=token;

    return token_feedback;
}

const char * create_token_feedback_message(token_feedback_t *feedback_data){
    const char * message;
    message=fill_with_va(TOKEN_FEEDBACK,4,
        feedback_data->session_id,
        feedback_data->user_name,
        feedback_data->res,
        feedback_data->token);

    return message;
}

int _response_request_callback(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp){
    
    // parse response
    response_request_t * response_request=parse_response_request(buf, buf_size);

    // query challenge
    const char * challenge; size_t challenge_len;
    int query_chal_res=query_challenge(my_connection, 
        response_request->session_id,
        response_request->user_name,
        &challenge);
    if (query_chal_res){
        fprintf(stderr,"query challenge gets problem");
        return 1;
    }

    // query public key
    EVP_PKEY * pubkey={0};
    int query_pkey_res=query_pubkey(my_connection, response_request->user_name, &pubkey);
    if (query_pkey_res){
        fprintf(stderr,"query pubkey gets problem");
        return 1;
    }

    // validate response 
    if (challenge){
        int validate_res= validate_signature(challenge, response_request->response, pubkey);
        if (validate_res==0){

            const char * token= generate_token();
            int record_res=record_token(my_connection, response_request->session_id, response_request->user_name, token);
            if (record_res==0){
                token_feedback_t * token_feedback=create_token_feedback(response_request,"0",token);
                *message_pp=create_token_feedback_message(token_feedback);
                
            }
            else{
                token_feedback_t * token_feedback=create_token_feedback(response_request,"1","");
                *message_pp=create_token_feedback_message(token_feedback);
                
            }
        }
        else{
            token_feedback_t * token_feedback=create_token_feedback(response_request,"1","");
            *message_pp=create_token_feedback_message(token_feedback);
            
        }
    }
    return 0;
}

int response_request_callback(SSL * ssl, MYSQL * my_connection, unsigned char * buf, size_t buf_size){
    const char * message;
    int res=_response_request_callback(my_connection, buf, buf_size, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}   

# endif