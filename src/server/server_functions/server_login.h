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
login_request_t * parse_login_request(const char * buf, size_t buf_size){

    login_request_t * login_request =_create_request(sizeof(login_request_t));
    get_with_va(buf, buf_size, 2, 
        &login_request->session_id, 
        &login_request->user_name);

    return login_request;
}

int create_login_request_callback_message(MYSQL* my_connection, const char * buf, size_t buf_size,const char ** message_pp){
   
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

    if (database_res){                                       // case 1: error 
       * message_pp=fill_with_va(CHALLENGE_FEEDBACK,4,              
        request_data->session_id, request_data->user_name,"1","server database get problems\n"); 
        return database_res;
    }
    else{                                                    // case 2: success 
        *message_pp=fill_with_va(CHALLENGE_FEEDBACK,4,
            request_data->session_id, request_data->user_name,"0",challenge); 
        return 0;
    }
        
    return 0;
}

int login_request_callback(SSL * ssl, MYSQL* my_connection, const char * buf, size_t buf_size){
    const char * message;
    int res=create_login_request_callback_message(my_connection,buf,buf_size,&message);
    SSL_write(ssl,message,strlen(message));
    return res;
}


/* response request */
response_request_t* parse_response_request(const char * buf, size_t buf_size){
    
    response_request_t * response_request=_create_request(sizeof(response_request_t));

    get_with_va(buf,buf_size,3,&response_request->session_id, &response_request->user_name, &response_request->response);
    return response_request;
}

int create_token_feedback_message(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp){
    
    // parse response
    response_request_t * response_request=parse_response_request(buf, buf_size);

    // query challenge
    const char * challenge; size_t challenge_len;
    int query_chal_res=query_challenge(my_connection, response_request->session_id, response_request->user_name, &challenge);
    if (query_chal_res){
        *message_pp=fill_with_va(TOKEN_FEEDBACK,4,response_request->session_id,response_request->user_name,"1","server database gets problem");
        return query_chal_res;
    }

    // query public key
    EVP_PKEY * pubkey={0};
    int query_pkey_res=query_pubkey(my_connection, response_request->user_name, &pubkey);
    if (query_pkey_res){
        *message_pp=fill_with_va(TOKEN_FEEDBACK,4,response_request->session_id,response_request->user_name,"1","server database gets problem");
        return query_pkey_res;
    }

    // validate response 
    if (challenge){
        int validate_res= validate_signature(challenge, response_request->response, pubkey);
        if (validate_res){
            *message_pp=fill_with_va(TOKEN_FEEDBACK,4,response_request->session_id,response_request->user_name,"1","invalid siganture");
        }
        else{

            const char * token= generate_token();
            int record_res=record_token(my_connection, response_request->session_id, response_request->user_name, token,"login");
            
            if (record_res){      
                *message_pp=fill_with_va(TOKEN_FEEDBACK,4,response_request->session_id,response_request->user_name,"1","server database gets problem");   
            }
            else{
                *message_pp=fill_with_va(TOKEN_FEEDBACK,4,response_request->session_id, response_request->user_name,"0",token);
            }
        }
        
    }
  
}

int response_request_callback(SSL * ssl, MYSQL * my_connection, char * buf, size_t buf_size){
    const char * message;
    int res=create_token_feedback_message(my_connection, buf, buf_size, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}   

/* quit request*/
// log out 要求过去的 token 变得无效，使用一个新的 token（不告知 client）
quit_request_t* parse_quit_request(const char * buf, size_t buf_size){
    
    quit_request_t * quit_request=_create_request(sizeof(quit_request_t));

    get_with_va(buf,buf_size,3,&quit_request->session_id, &quit_request->user_name, &quit_request->token);
    return quit_request;
}

int create_quit_feedback_message(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp){
    
    // parse response
    quit_request_t * quit_request=parse_quit_request(buf, buf_size);
    
    int validate_res=validate_token(my_connection,
        quit_request->session_id,
        quit_request->user_name,
        quit_request->token);

    if (validate_res){
        * message_pp=fill_with_va(QUIT_FEEDBACK,4,quit_request->session_id,quit_request->user_name,"1","server gets problem");
        return validate_res;
    }
    else{
        const char * token= generate_token();
        int record_res=record_token(my_connection, quit_request->session_id, quit_request->user_name, token,"quit");
        
        if (record_res){      
            *message_pp=fill_with_va(QUIT_FEEDBACK,4,quit_request->session_id,quit_request->user_name,"1","server gets problem");   
        }
        else{
            *message_pp=fill_with_va(QUIT_FEEDBACK,4,quit_request->session_id, quit_request->user_name,"0","");
        }
    }

}

int quit_request_callback(SSL * ssl, MYSQL * my_connection, char * buf, size_t buf_size){
    const char * message;
    int res=create_quit_feedback_message(my_connection, buf, buf_size, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}   



# endif