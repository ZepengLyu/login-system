# ifndef CLIENT_FUNCTIONS_H
# define CLIENT_FUNCTIONS_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../config.h"
# include "../common.h"
# include "../message_type.h"
# include "../crypto.h"


// register
register_request_t * create_register_request(
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size, const char * email, size_t email_size,
    const unsigned char * pkey,size_t pkey_size){
    
    register_request_t * register_request=_create_register_request();

    register_request->session_id=session_id;
    register_request->session_id_size=session_id_size;

    register_request->user_name=user_name;
    register_request->username_size=username_size;

    register_request->email=email;
    register_request->email_size=email_size;

    register_request->pubkey=pkey;
    register_request->pubkey_size=pkey_size;

    return register_request;
}

int create_register_request_message(const unsigned char ** message_pp, size_t * message_size_p, register_request_t * register_request){    

    fill_with_va(message_pp, message_size_p, REGISTER_TYPE,4,
        register_request->session_id,register_request->session_id_size,
        (const unsigned char *) register_request->user_name, register_request->username_size,
        (const unsigned char *) register_request->email, register_request->email_size,
        register_request->pubkey, register_request->pubkey_size
       );
    return 0;
}

register_token_request_t * create_register_token_request(
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const unsigned char * token,size_t token_size){
    
    register_token_request_t * register_token_request=_create_register_token_request();

    register_token_request->session_id=session_id;
    register_token_request->session_id_size=session_id_size;

    register_token_request->user_name=user_name;
    register_token_request->username_size=username_size;

    register_token_request->token=token;
    register_token_request->token_size=token_size;
    
    return register_token_request;
}

int create_register_token_request_message(const unsigned char ** message_pp, size_t * message_size_p, register_token_request_t * register_token_request){    

    fill_with_va(message_pp, message_size_p, REGISTER_TYPE,3,
        register_token_request->session_id,register_token_request->session_id_size,
        (const unsigned char *) register_token_request->user_name, register_token_request->username_size,
        register_token_request->token, register_token_request->token_size
       );
    return 0;
}




// login
login_request_t * create_login_request( 
    const unsigned char * session_id, size_t session_id_size,
    const char *user_name, size_t username_size){

    login_request_t* login_request=_create_login_request(); 

    login_request->session_id=session_id;
    login_request->session_id_size=session_id_size;

    login_request->user_name=user_name;
    login_request->username_size=username_size;        
    
    return login_request;
}

int create_login_request_message(const unsigned char ** message_pp, size_t * message_size_p, login_request_t * login_request){
      
    fill_with_va(message_pp, message_size_p, LOGIN_TYPE,2,
        login_request->session_id, login_request->session_id_size,
        (const unsigned char *) login_request->user_name, login_request->username_size
       );
    return 0;
}


// response

challenge_feedback_t * parse_challenge_feedback(const unsigned char * buf, size_t buf_size){

    challenge_feedback_t * challenge_feedback=_create_challenge_feedback();
    get_with_va(buf,buf_size,3,
        &challenge_feedback->session_id, &challenge_feedback->session_id_size,
        &challenge_feedback->user_name, &challenge_feedback->username_size,
        &challenge_feedback->challenge, &challenge_feedback->challenge_size
    );
    return challenge_feedback;
}

int check_token(token_feedback_t *token_feedback, const unsigned char * session_id, size_t session_id_size,  const char * user_name, size_t user_name_size){
     
    int identical_flag=0;
    identical_flag=memcmp(token_feedback->session_id,session_id,session_id_size);
    identical_flag=memcmp(token_feedback->user_name,user_name,user_name_size);
    return identical_flag;

}
int check_challenge_feedback(challenge_feedback_t *client_challenge_feedback, const unsigned char * session_id, size_t session_id_size,  const char * user_name, size_t user_name_size)
{   
    int identical_flag=0;
    identical_flag=memcmp(client_challenge_feedback->session_id,session_id,session_id_size);
    identical_flag=memcmp(client_challenge_feedback->user_name,user_name,user_name_size);
    return identical_flag;

}
response_request_t * create_response_request(challenge_feedback_t * challenge_feedback ,const unsigned char * signature, size_t signature_size){
    
    response_request_t * response_request=_create_response_request();

    response_request->session_id=challenge_feedback->session_id;
    response_request->session_id_size=challenge_feedback->session_id_size;

    response_request->user_name=challenge_feedback->user_name;
    response_request->username_size=challenge_feedback->username_size;

    response_request->response=signature;
    response_request->response_size=signature_size;

    return response_request;

}

int create_response_request_message(unsigned char ** message_pp, size_t * message_size_p, 
  response_request_t * response_request){
    fill_with_va(message_pp, message_size_p, RESPONSE_TYPE,3,
        response_request->session_id, response_request->session_id_size,
        (const unsigned char *) response_request->user_name, response_request->username_size,
        response_request->response, response_request->response_size);
    return 0;
}

// token
token_feedback_t * parse_token_feedback(const unsigned char * buf, size_t buf_size){
    
    token_feedback_t * token_feedback=_create_token_feedback();

    get_with_va(buf,buf_size,3,
        &token_feedback->session_id, &token_feedback->session_id_size,
        &token_feedback->user_name, &token_feedback->username_size,
        &token_feedback->token, &token_feedback->token_size
    );

    return token_feedback;
}



// data request
update_request_t * create_update_request(
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const char * data, size_t data_size,
    const unsigned char * token, size_t token_size){

    update_request_t * update_request=_create_update_request();

    update_request->session_id=session_id;
    update_request->session_id_size=session_id_size;
    
    update_request->user_name=user_name;
    update_request->username_size=username_size;
    
    update_request->data=data;
    update_request->data_size=data_size;
    
    update_request->token=token;
    update_request->token_size=token_size;
    
    return update_request;
}

int create_update_request_message(unsigned char ** message_pp, size_t * message_size_p,
    update_request_t * update_request){
    
    fill_with_va(message_pp, message_size_p, DATA_UPDATE_TYPE,4,
        update_request->session_id, update_request->session_id_size,
        (const unsigned char *) update_request->user_name, update_request->username_size,
        (const unsigned char *) update_request->data, update_request->data_size,
        update_request->token, update_request->token_size
       );
    return 0;
   
}




query_request_t * create_query_request(const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const unsigned char * token, size_t token_size){
    
    query_request_t * query_request=_create_update_request();
    query_request->session_id=session_id;
    query_request->session_id_size=session_id_size;
    query_request->user_name=user_name;
    query_request->username_size=username_size;
    query_request->token=token;
    query_request->token_size=token_size;
    return query_request;
}

int create_query_request_message(unsigned char ** message_pp, size_t * message_size_p,
    query_request_t * query_request){
    
    fill_with_va(message_pp, message_size_p, DATA_QUERY_TYPE,3,
        query_request->session_id, query_request->session_id_size,
        query_request->user_name, query_request->username_size,
        query_request->token,query_request->token_size
       );
    return 0;
   
}


// change factor

change_factor_request_t * create_change_factor_request(
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size){

    change_factor_request_t * change_factor_request=_create_change_factor_request();
    
    change_factor_request->session_id=session_id;
    change_factor_request->session_id_size=session_id_size;

    change_factor_request->user_name=user_name;
    change_factor_request->username_size=username_size;

    return change_factor_request;
}

int create_change_factor_request_message(const unsigned char ** message_pp, size_t * message_size_p, change_factor_request_t * change_factor_request){
    
    fill_with_va(message_pp, message_size_p, CHANGE_FACTOR_TYPE,2,
        change_factor_request->session_id, change_factor_request->session_id_size,
        (const unsigned char *) change_factor_request->user_name, change_factor_request->username_size
       );
    return 0;
    
}


change_factor_token_request_t * create_change_factor_token_request(
    const unsigned char * session_id, size_t session_id_size,
    const char * user_name, size_t username_size,
    const unsigned char * new_public_key, size_t new_public_key_size,
    const unsigned char * token, size_t token_size){
        
        change_factor_token_request_t * change_factor_token=_create_change_factor_token_request();

    change_factor_token->session_id=session_id;
    change_factor_token->session_id_size=session_id_size;
    
    change_factor_token->user_name=user_name;
    change_factor_token->username_size=username_size;
    
    change_factor_token->new_pubkey=new_public_key;
    change_factor_token->new_pubkey_size=new_public_key_size;
    
    change_factor_token->token=token;
    change_factor_token->token_size=token_size;

    return change_factor_token;
}

int create_change_factor_token_request_message(const unsigned char ** message_pp, size_t * message_size_p,
    change_factor_token_request_t * change_factor_token_request){
    
    fill_with_va(message_pp, message_size_p, CHANGE_FACTOR_TOKEN_TYPE,4,
        change_factor_token_request->session_id, change_factor_token_request->session_id_size,
        (const unsigned char *) change_factor_token_request->user_name, change_factor_token_request->username_size,
        change_factor_token_request->new_pubkey, change_factor_token_request->new_pubkey_size,
        change_factor_token_request->token, change_factor_token_request->token_size
       );
    return 0;
   
}








    


# endif