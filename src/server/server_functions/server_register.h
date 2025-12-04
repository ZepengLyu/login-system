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

register_permission_feedback_t * create_register_permission_feedback( const char * session_id, const char * user_name, const char * res, const char * message){
    register_permission_feedback_t *feedback=_create_feedback(sizeof(register_permission_feedback_t));

    feedback->session_id=session_id;
    feedback->user_name=user_name;
    feedback->res=res;
    feedback->message=message;

    return feedback;
}

const char * create_register_permission_feedback_message (register_permission_feedback_t * feedback){
    const char * message= fill_with_va( REGISTER_PERMISSION_FEEDBACK,4,
        feedback->session_id,
        feedback->user_name,
        feedback->res,
        feedback->message
       );
    
    return message;
};

int _register_request_callback(MYSQL* my_connection,const char * buf, size_t buf_size, const char ** message_pp,const char ** email_token_pp){
   
    // parse register request
    register_request_t *register_request=parse_register_request(buf, buf_size);
    
    // validate username 
    int validate_res=validate_username(my_connection,register_request->user_name);
    if (validate_res==0){
        const char * email_token = generate_email_token();
        size_t email_token_size=sizeof(email_token)+1;

        int record_res=record_email_token(my_connection,
            register_request->session_id,
            register_request->user_name,
            register_request->email,
            register_request->pubkey,
            email_token);

        
        if (record_res==0){
            if (send_email(register_request->email,email_token,strlen(email_token))==0){
                *email_token_pp=email_token;
                register_permission_feedback_t * feedback=create_register_permission_feedback(
                    register_request->session_id,
                    register_request->user_name,
                    "0",
                    "the token email has been sent to the designated email");
                
                    * message_pp=create_register_permission_feedback_message(feedback);
               
            }   
            else{
                register_permission_feedback_t * feedback=create_register_permission_feedback(
                    register_request->session_id,
                    register_request->user_name,
                    "1",
                    "the server email system encounters some problem");
                
                    * message_pp=create_register_permission_feedback_message(feedback);

            }
        }
        else{
            register_permission_feedback_t * feedback=create_register_permission_feedback(
                register_request->session_id,
                register_request->user_name,
                "1",
                "the server database system encounters some problem");
            
                * message_pp=create_register_permission_feedback_message(feedback);
        }
    }
    else if (validate_res==1){
        register_permission_feedback_t * feedback=create_register_permission_feedback(
            register_request->session_id,
            register_request->user_name,
            "1",
            "this username has been registered");
        
        * message_pp=create_register_permission_feedback_message(feedback);
    }
    return 0;
}

int register_request_callback(SSL * ssl, MYSQL* my_connection,const char * buf, size_t buf_size){
    const char * message;
    const char * email_token;
    int res=_register_request_callback(my_connection,buf,buf_size,&message,&email_token);
    SSL_write(ssl,message,strlen(message)+1);
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

register_result_feedback_t * create_register_if_success_feedback(const char * session_id, const char * user_name, const char * res, const char * message) {
    register_result_feedback_t * feedback = _create_feedback(sizeof(register_result_feedback_t));
    feedback->session_id = session_id;
    feedback->user_name = user_name;
    feedback->res = res;
    feedback->message = message;

    return feedback;
}

const char * create_register_if_success_feedback_message(register_result_feedback_t * feedback) {
    const char * message = fill_with_va(REGISTER_RESULT_FEEDBACK, 4,
        feedback->session_id,
        feedback->user_name,
        feedback->res,
        feedback->message
    );
    return message;
}

int _register_token_request_callback(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp) {
    
    // Parse register token request
    register_token_request_t * register_token_request = parse_register_token_request(buf, buf_size);

    // Validate token
    const char * ret_email;
    const char * ret_pubkey;
    int validate_res = validate_email_token(my_connection, 
        register_token_request->session_id, register_token_request->user_name, register_token_request->token, 
        & ret_email, & ret_pubkey);
    if (validate_res == 0) {

        // Token is valid, acknowledge registration
        int record_res = record_register(my_connection, register_token_request->user_name,ret_email,ret_pubkey);

        if (record_res == 0) {
            register_result_feedback_t * feedback = create_register_if_success_feedback(
                register_token_request->session_id,
                register_token_request->user_name,
                "0",
                "Registration success successfully"
            );

            *message_pp = create_register_if_success_feedback_message(feedback);
            
        } else {
            register_result_feedback_t * feedback = create_register_if_success_feedback(
                register_token_request->session_id,
                register_token_request->user_name,
                "1",
                "Failed to record registration in the database"
            );

            *message_pp = create_register_if_success_feedback_message(feedback);
           
        }
    } 
    else {
        // Token is invalid
        register_result_feedback_t * feedback = create_register_if_success_feedback(
            register_token_request->session_id,
            register_token_request->user_name,
            "1",
            "Invalid token"
        );

        *message_pp = create_register_if_success_feedback_message(feedback);
        
    }

    return 0;
}

int register_token_request_callback(SSL * ssl, MYSQL * my_connection, const char * buf, size_t buf_size){
    const char * message;
    int res=_register_token_request_callback(my_connection,buf,buf_size,&message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}

/* register token request callback */




#endif