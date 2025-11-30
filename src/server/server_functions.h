# ifndef SERVER_FUNCTIONS_H
# define SERVER_FUNCTIONS_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "./database.h"
#include "../config.h"
#include "../common.h"
#include "../message_type.h"
#include "../crypto.h"

// general feedback 
general_feedback_t * create_general_feedback(const unsigned char * session_id, size_t session_id_size, 
    const char *user_name, size_t user_name_size, 
    const char * message, size_t message_size){
    
    general_feedback_t * general_feedback=_create_general_feedback();

    general_feedback->session_id=session_id;
    general_feedback->session_id_size=session_id_size;
    
    general_feedback->user_name=user_name;
    general_feedback->username_size=user_name_size;
    
    general_feedback->message=message;
    general_feedback->message_size=message_size;
    
    return general_feedback;
}

int create_general_feedback_message(const unsigned char ** text_pp, size_t * text_len_p, general_feedback_t* feedback_data)
{
    fill_with_va(text_pp, text_len_p, FEEDBACK_TYPE,3,
        feedback_data->session_id,feedback_data->session_id_size,
        (const unsigned char *) feedback_data->user_name, feedback_data->username_size, 
        (const unsigned char *) feedback_data->message, feedback_data->message_size);
    return 0;
}



// register

register_request_t *  parse_register_request(const unsigned char * buf, size_t buf_size){
    register_request_t * register_request=_create_register_request();

    get_with_va(buf, buf_size,4,
        &register_request->session_id, &register_request->session_id_size, 
        &register_request->user_name, &register_request->username_size,
        &register_request->email, &register_request->email_size, 
        &register_request->pubkey, &register_request->pubkey_size);
    
    return register_request;
}

register_token_request_t * parse_register_token_request_message(const unsigned char * buf, size_t buf_size){
    register_token_request_t * register_token_request=_create_register_token_request();

    get_with_va(buf, buf_size,3,
        &register_token_request->session_id, &register_token_request->session_id_size, 
        &register_token_request->user_name, &register_token_request->username_size,
        &register_token_request->token, &register_token_request->token_size);
    
    return register_token_request;
}

// login

login_request_t * parse_login_request(const unsigned char *buf, size_t buf_size){

    login_request_t * login_request =_create_login_request();

    get_with_va(buf, buf_size, 2, 
        &login_request->session_id, 
        &login_request->session_id_size,
        &login_request->user_name,
        &login_request->username_size);

    return login_request;
}

challenge_feedback_t * create_challenge_feedback(login_request_t * request_data){

    challenge_feedback_t * challenge_feedback=_create_challenge_feedback();
    
    challenge_feedback->session_id=request_data->session_id;
    challenge_feedback->session_id_size=request_data->session_id_size;
    challenge_feedback->user_name=request_data->user_name;
    challenge_feedback->username_size=request_data->username_size;

    challenge_feedback->challenge=generate_challenge();
    challenge_feedback->challenge_size=CHALLENGE_SIZE;

    return challenge_feedback;
}

int create_challenge_feedback_message(const unsigned char ** message, size_t * message_size, challenge_feedback_t * feedback_data){
    fill_with_va(message,message_size,CHALLENGE_TYPE,3,
        feedback_data->session_id,
        feedback_data->session_id_size,
        feedback_data->user_name,
        feedback_data->username_size,
        feedback_data->challenge,
        feedback_data->challenge_size
    );
    return 0;
}

int login_callback(SSL * ssl, MYSQL* my_connection, unsigned char * buf, size_t buf_size){
   
    // parse buf
    login_request_t * request_data=parse_login_request(buf, buf_size);

    challenge_feedback_t * feedback_data=create_challenge_feedback(request_data);

    const unsigned char * message={0}; size_t message_size={0};
    create_challenge_feedback_message(&message,&message_size,feedback_data);

    // send challenge_text
    SSL_write(ssl,message,message_size);
    
    // login record
    record_login(my_connection, 
        feedback_data->session_id,feedback_data->session_id_size,
        feedback_data->user_name,feedback_data->username_size,
        feedback_data->challenge,feedback_data->challenge_size
    );

    return 0;
}





response_request_t* parse_response_request(unsigned char * buf, size_t buf_size){
    
    response_request_t * response_request=_create_response_request();

    get_with_va(buf,buf_size,3,
        &response_request->session_id,
        &response_request->session_id_size,
        &response_request->user_name,
        &response_request->username_size,
        &response_request->response,
        &response_request->response_size
    );
    return response_request;
}


token_feedback_t * create_token_feedback( response_request_t * request_data){

    token_feedback_t * token_feedback=_create_token_feedback();

    token_feedback->session_id=request_data->session_id;
    token_feedback->session_id_size=request_data->session_id_size;
    token_feedback->user_name=request_data->user_name;
    token_feedback->username_size=request_data->username_size;

    const unsigned char * token=generate_token(); size_t token_size=TOKEN_SIZE;

    token_feedback->token=token;
    token_feedback->token_size=token_size;

    return token_feedback;
}

int create_token_feedback_message(const unsigned char ** text_pp, size_t * text_len_p,token_feedback_t *feedback_data ){

    fill_with_va(text_pp,text_len_p,TOKEN_TYPE,3,
        feedback_data->session_id,feedback_data->session_id_size,
        feedback_data->user_name,feedback_data->username_size,
        feedback_data->token,feedback_data->token_size);

    return 0;
}



// update request and query request callback
update_request_t *  parse_update_request(const unsigned char * buf, size_t buf_size)
{   
    update_request_t * update_request=_create_update_request();
    get_with_va(buf,buf_size,4,
        &update_request->session_id, &update_request->session_id_size,
        &update_request->user_name, &update_request->username_size,
        &update_request->data, &update_request->data_size,
        &update_request->token, &update_request->token_size
    );
    return update_request;
}

query_request_t * parse_query_request(const unsigned char * buf, size_t buf_size)
{
    query_request_t * query_request=_create_query_request();
    get_with_va(buf,buf_size,3,
        &query_request->session_id, &query_request->session_id_size,
        &query_request->user_name, &query_request->username_size,
        &query_request->token, &query_request->token_size
    );
    return query_request;
}


change_factor_request_t * parse_change_factor_request(const unsigned char * buf, size_t buf_size)
{
    change_factor_request_t * change_factor_request =_create_change_factor_request();
    get_with_va(buf,buf_size,2,
        &change_factor_request->session_id, &change_factor_request->session_id_size,
        &change_factor_request->user_name, &change_factor_request->username_size
    );
    return change_factor_request;

}

change_factor_token_request_t * parse_change_factor_token_request(const unsigned char * buf, size_t buf_size)
{
    change_factor_token_request_t * change_factor_token_request =_create_change_factor_token_request();
    get_with_va(buf,buf_size,4,
        &change_factor_token_request->session_id, &change_factor_token_request->session_id_size,
        &change_factor_token_request->user_name, &change_factor_token_request->username_size,
        &change_factor_token_request->new_pubkey, &change_factor_token_request->new_pubkey_size,
        &change_factor_token_request->token, &change_factor_token_request->token_size
    );
    return change_factor_token_request;

}



# endif