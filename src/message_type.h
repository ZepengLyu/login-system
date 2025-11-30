#ifndef MESSAGE_TYPE_H
#define MESSAGE_TYPE_H
#include <stdlib.h>

# define REGISTER_TYPE '0'
# define LOGIN_TYPE '1'
# define CHALLENGE_TYPE '2'
# define RESPONSE_TYPE '3'
# define TOKEN_TYPE '4'
# define FEEDBACK_TYPE '5'
# define DATA_UPDATE_TYPE '6'
# define DATA_QUERY_TYPE '7'
# define CHANGE_FACTOR_TYPE '8'
# define CHANGE_FACTOR_TOKEN_TYPE '9'

typedef struct{
    const unsigned char  * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const char * email;  size_t email_size;
    const unsigned char * pubkey; size_t pubkey_size;
} register_request_t;


typedef struct{
    const unsigned char  * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * token; size_t token_size;
} register_token_request_t; 

typedef struct{
    const unsigned char  * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
} login_request_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * challenge; size_t challenge_size;
} challenge_feedback_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * response; size_t response_size;
} response_request_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * token; size_t token_size;
} token_feedback_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const char * message;  size_t message_size;
} general_feedback_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
} change_factor_request_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * new_pubkey; size_t new_pubkey_size;
    const unsigned char * token;  size_t token_size;
} change_factor_token_request_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const char * data; size_t data_size;
    const unsigned char * token; size_t token_size; 
} update_request_t;

typedef struct{
    const unsigned char * session_id; size_t session_id_size;
    const char * user_name;  size_t username_size;
    const unsigned char * token; size_t token_size; 
} query_request_t;

register_request_t * _create_register_request(){
    register_request_t * register_request= (register_request_t *)malloc(sizeof(register_request_t));
    memset(register_request,0,sizeof(register_request_t));
    return register_request;
}

register_token_request_t * _create_register_token_request(){
    register_token_request_t * register_token_request= (register_token_request_t *)malloc(sizeof(register_token_request_t));
    memset(register_token_request,0,sizeof(register_token_request_t));
    return register_token_request;
}

login_request_t * _create_login_request(){
    login_request_t * login_request= (login_request_t *)malloc(sizeof(login_request_t));
    memset(login_request,0,sizeof(login_request_t));
    return login_request;
}
challenge_feedback_t * _create_challenge_feedback(){
    challenge_feedback_t * challenge_feedback= (challenge_feedback_t *)malloc(sizeof(challenge_feedback_t));
    memset(challenge_feedback,0,sizeof(challenge_feedback_t));
    return challenge_feedback;
}
response_request_t * _create_response_request(){     
    response_request_t * response_request= (response_request_t *)malloc(sizeof(response_request_t));
    memset(response_request,0,sizeof(response_request_t));
    return response_request;
}
token_feedback_t * _create_token_feedback(){
    token_feedback_t * token_feedback= (token_feedback_t *)malloc(sizeof(token_feedback_t));
    memset(token_feedback,0,sizeof(token_feedback_t));
    return token_feedback;
}
general_feedback_t * _create_general_feedback(){
    general_feedback_t * general_feedback= (general_feedback_t *)malloc(sizeof(general_feedback_t));
    memset(general_feedback,0,sizeof(general_feedback_t));
    return general_feedback;
}
change_factor_request_t * _create_change_factor_request(){
    change_factor_request_t * change_factor_request= (change_factor_request_t *)malloc(sizeof(change_factor_request_t));
    memset(change_factor_request,0,sizeof(change_factor_request_t));
    return change_factor_request;
}
change_factor_token_request_t * _create_change_factor_token_request(){
    change_factor_token_request_t * change_factor_token= (change_factor_token_request_t *)malloc(sizeof(change_factor_token_request_t));
    memset(change_factor_token,0,sizeof(change_factor_token_request_t));
    return change_factor_token;
}
update_request_t * _create_update_request(){
    update_request_t * update_request= (update_request_t *)malloc(sizeof(update_request_t));
    memset(update_request,0,sizeof(update_request_t));
    return update_request;
}
query_request_t * _create_query_request(){
    query_request_t * query_request= (query_request_t *)malloc(sizeof(query_request_t));
    memset(query_request,0,sizeof(query_request_t));
    return query_request;
}           
#endif