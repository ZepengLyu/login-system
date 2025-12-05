# ifndef SERVER_CHANGE_FACTOR_H
# define SERVER_CHANGE_FACTOR_H
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

// parse request
change_factor_request_t * parse_change_factor_request(const char * buf, size_t buf_size)
{
    change_factor_request_t * change_factor_request =_create_request(sizeof(change_factor_request_t));
    get_with_va(buf,buf_size,2,
        &change_factor_request->session_id, 
        &change_factor_request->user_name
    );
    return change_factor_request;
}
// feedback
change_factor_feedback_t *create_change_factor_feedback(const char * session_id, const char * user_name, const char * res, const char* content){
    change_factor_feedback_t * feedback =_create_request(sizeof(change_factor_feedback_t));
    feedback->session_id=session_id;
    feedback->user_name=user_name;
    feedback->res=res;
    feedback->data=content;
    return feedback;
}

const char * create_change_factor_feedback_message(change_factor_feedback_t *feedback){
    const char * message;
    message=fill_with_va(CHANGE_FACTOR_FEEDBACK,4,
        feedback->session_id,
        feedback->user_name,
        feedback->res,
        feedback->data);
    return message;
}

int _change_factor_request_callback(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp,const char ** email_token_pp){

    // parse request
    change_factor_request_t * change_factor_request= parse_change_factor_request(buf,buf_size);
   
    // query email as the recipient
    const char * email; 
    int query_email_res=query_email(my_connection, change_factor_request->user_name, &email);

    if (query_email_res){                // case 1: error
        * message_pp=NULL;
        return query_email_res; 
    }
    else{                 
        // record and generate email token
        const char * email_token = generate_email_token();
        int record_email_token=record_change_factor_token(my_connection, change_factor_request->session_id, change_factor_request->user_name, email_token);
        if (record_email_token){         // case 2: error
            * message_pp=NULL;
            return record_email_token; 
        } 
        else{                          
            int send_email_res=send_email(email,email_token,strlen(email_token));
            if (send_email_res){         // case 3: error
                * message_pp=NULL;
                return send_email_res;
            }      
            else{                       // case 4: success
                change_factor_feedback_t * feedback=create_change_factor_feedback(change_factor_request->session_id,change_factor_request->user_name,"0","the email has been sent to the designated email"); 
                // * email_token_pp=email_token; // used in test 
                * message_pp=create_change_factor_feedback_message(feedback);
            }
            return 0;                    
        }
    }
    return -1; 
}


int change_factor_request_callback(SSL *ssl, MYSQL * my_connection, const char * buf, size_t buf_size){
    const char * message;
   _change_factor_request_callback(my_connection, buf,buf_size,&message ,NULL);    
    SSL_write(ssl,message,strlen(message));
    return 0;
}

/* round 2 */

// parse request
change_factor_token_request_t * parse_change_factor_token_request(const char * buf, size_t buf_size)
{
    change_factor_token_request_t * change_factor_token_request =_create_request(sizeof(change_factor_token_request_t));
    get_with_va(buf,buf_size,4,
        &change_factor_token_request->session_id, 
        &change_factor_token_request->user_name,
        &change_factor_token_request->new_pubkey,
        &change_factor_token_request->token
    );
    return change_factor_token_request;
}

change_factor_token_feedback_t *create_change_factor_token_feedback(const char * session_id, const char * user_name, const char * res, const char* content){
    change_factor_token_feedback_t * feedback =_create_request(sizeof(change_factor_token_feedback_t));
    feedback->session_id=session_id;
    feedback->user_name=user_name;
    feedback->res=res;
    feedback->data=content;
    return feedback;
}

const char * create_change_factor_token_feedback_message(change_factor_token_feedback_t *feedback){
    const char * message;
    message=fill_with_va(CHANGE_FACTOR_TOKEN_FEEDBACK,4,
        feedback->session_id,
        feedback->user_name,
        feedback->res,
        feedback->data);
    return message;
}


int _change_factor_token_request_callback(MYSQL * my_connection, const char * buf, size_t buf_size,const char ** message_pp){
    
    change_factor_token_request_t * change_factor_token_request = parse_change_factor_token_request(buf,buf_size);

    int validate_res=validate_change_factor_token(my_connection, change_factor_token_request->session_id, change_factor_token_request->user_name, change_factor_token_request->token);
    
    if (validate_res){              // case 1: error
        *message_pp=NULL;
        return validate_res;
    }
    else{
        int update_res=update_pubkey(my_connection, change_factor_token_request->user_name, change_factor_token_request->new_pubkey);
        
        if (update_res){            // case 2: error
            *message_pp=NULL;
            return update_res;
        }
        else{                       // case 3: success
            change_factor_token_feedback_t * feedback=create_change_factor_token_feedback(change_factor_token_request->session_id, change_factor_token_request->user_name, "0","public key update success");
            * message_pp=create_change_factor_token_feedback_message(feedback);
            return 0;
        }   
    }
}

int change_factor_token_request_callback(SSL *ssl, MYSQL * my_connection, const char * buf, size_t buf_size){
    const char * message;
    int res=_change_factor_token_request_callback(my_connection, buf, buf_size, &message);
    SSL_write(ssl,message,strlen(message));
    return res;
}
#endif