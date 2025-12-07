# ifndef SERVER_REGISTER_H
# define SERVER_REGISTER_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "./server_database.h"
#include "./server_email.h"
#include "../../config.h"
#include "../../common.h"
#include "../../message_type.h"
#include "../../crypto.h"


/* register request callback */

register_request_t *  parse_register_request(const char * buf, size_t buf_size){
    register_request_t * register_request=_create_request(sizeof(register_request_t));

    get_with_va(buf, buf_size,4,
        &register_request->session_id, 
        &register_request->user_name,
        &register_request->email,
        &register_request->pubkey);
    
    return register_request;
}

int create_register_permission_feedback_message(MYSQL* my_connection,const char * buf, size_t buf_size, const char ** message_pp,const char ** email_token_pp){
   
    // parse register request
    register_request_t *register_request=parse_register_request(buf, buf_size);
    
    // validate username 
    int validate_res=validate_username(my_connection,register_request->user_name);
    if (validate_res){                                                           // case 1: error       
        * message_pp=fill_with_va(REGISTER_PERMISSION_FEEDBACK,4, 
            register_request->session_id, register_request->user_name,"1", "this username has been registered");
    }
    else{                                                              
        const char * email_token = generate_email_token();
        size_t email_token_size=sizeof(email_token)+1;

        int record_res=pre_record_register(my_connection, register_request->session_id, register_request->user_name,
            register_request->email, register_request->pubkey,email_token);

        if(record_res){                                                         // case 2: error
            * message_pp=fill_with_va(REGISTER_PERMISSION_FEEDBACK,4,
                register_request->session_id, register_request->user_name,"1", "the server database system encounters some problem");
        }                
        else{
            int send_res=send_email(register_request->email,email_token,strlen(email_token));
            if (send_res){                                                      // case 3: error
                * message_pp=fill_with_va(REGISTER_PERMISSION_FEEDBACK,4,
                    register_request->session_id,register_request->user_name, "1", "the server email system encounters some problem");
            }
            else{                                                                // case 4: success
                *email_token_pp=email_token;    
                * message_pp=fill_with_va(REGISTER_PERMISSION_FEEDBACK,4,
                    register_request->session_id,register_request->user_name,"0","the token email has been sent to the designated email");
            }   
        }
    }
   
    return 0;
}

int register_request_callback(SSL * ssl, MYSQL* my_connection,const char * buf, size_t buf_size){
    const char * message;
    const char * email_token;
    int res=create_register_permission_feedback_message(my_connection,buf,buf_size,&message,&email_token);
    SSL_write(ssl,message,strlen(message));
    return res;
}


/* register token request callback */

register_token_request_t * parse_register_token_request(const char * buf, size_t buf_size) {

    register_token_request_t * register_token_request = _create_request(sizeof(register_token_request_t));

    get_with_va(buf, buf_size, 3,
        &register_token_request->session_id,
        &register_token_request->user_name,
        &register_token_request->token
    );

    return register_token_request;
}

int create_register_result_feedback_message(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp) {
    
    // Parse register token request
    register_token_request_t * register_token_request = parse_register_token_request(buf, buf_size);

    // Validate token
    int validate_res = validate_email_token(my_connection, register_token_request->session_id, register_token_request->user_name, register_token_request->token,"register");

    if (validate_res) {
        *message_pp =fill_with_va(REGISTER_RESULT_FEEDBACK,4, register_token_request->session_id, register_token_request->user_name, "1", "Invalid token");
    }
    else{
        // Token is valid, acknowledge registration
        const char * email;
        int query_email_res=query_register_email(my_connection, register_token_request->session_id, register_token_request->user_name, register_token_request->token,&email);
        const char * pubkey;
        int query_pubkey_res=query_register_pubkey(my_connection, register_token_request->session_id, register_token_request->user_name, register_token_request->token,&pubkey);

        if (query_email_res || query_pubkey_res){
            *message_pp =fill_with_va(REGISTER_RESULT_FEEDBACK,4, register_token_request->session_id, register_token_request->user_name,"1","Server database gets problem");    
        }
        else{
            int record_res = record_register(my_connection, register_token_request->user_name,email,pubkey);
            if (record_res == 0) {
                *message_pp =fill_with_va(REGISTER_RESULT_FEEDBACK,4, register_token_request->session_id, register_token_request->user_name,"0","Registration success successfully");    
            } 
            else {
                *message_pp = *message_pp =fill_with_va(REGISTER_RESULT_FEEDBACK,4, register_token_request->session_id, register_token_request->user_name, "1","Server database gets problem");
            }
        }
    } 
}

int register_token_request_callback(SSL * ssl, MYSQL * my_connection, const char * buf, size_t buf_size){
    const char * message;
    int res=create_register_result_feedback_message(my_connection,buf,buf_size,&message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}


#endif