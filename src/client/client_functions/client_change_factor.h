
# ifndef CLIENT_CHANGE_FACTOR_H
# define CLIENT_CHANGE_FACTOR_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"

/* round 1 */

change_factor_request_t * create_change_factor_request(const char * session_id, const char * user_name){

    change_factor_request_t * change_factor_request=_create_request(sizeof(change_factor_request_t));
    change_factor_request->session_id=session_id;
    change_factor_request->user_name=user_name;
    return change_factor_request;
}

const char * create_change_factor_request_message(change_factor_request_t * change_factor_request){   

    const char * message;
    message= fill_with_va( CHANGE_FACTOR_REQUEST,2,
        change_factor_request->session_id,change_factor_request->user_name
       );
    return message;
}

int _change_factor_request(const char * session_id, const char * user_name,const char ** message_pp){
    change_factor_request_t * request=create_change_factor_request(session_id, user_name);
    *message_pp=create_change_factor_request_message(request);
    return 0;
}

int change_factor_request(SSL *ssl, const char * session_id, const char * user_name){
    const char * message;
    _change_factor_request(session_id,user_name,&message);
    SSL_write(ssl,message,strlen(message));
    return 0;
}
/* round 2*/

change_factor_token_request_t * create_change_factor_token_request(const char * session_id, const char * user_name, const char * new_public_key, const char * token){
        
    change_factor_token_request_t * change_factor_token=_create_request(sizeof(change_factor_token_request_t));

    change_factor_token->session_id=session_id;
    change_factor_token->user_name=user_name;
    change_factor_token->new_pubkey=new_public_key;
    change_factor_token->token=token;

    return change_factor_token;
}

const char * create_change_factor_token_request_message(change_factor_token_request_t * change_factor_token_request){
    
    const char * message;
    message=fill_with_va(CHANGE_FACTOR_TOKEN_REQUEST,4,
        change_factor_token_request->session_id, 
        change_factor_token_request->user_name,
        change_factor_token_request->new_pubkey, 
        change_factor_token_request->token
       );
    return message;
}

int _change_factor_token_request(const char * session_id, const char * user_name,const char * email_token,const char ** message_pp){

    const char *new_pubkey;
    int generate_res=generate_keypair(&new_pubkey,CLIENT_PRIVATEKEY_FILE);
    change_factor_token_request_t * request=create_change_factor_token_request(session_id, user_name, new_pubkey,email_token);
    * message_pp=create_change_factor_token_request_message(request);
    return 0;
}

int change_factor_token_request(SSL *ssl,const char * session_id, const char * user_name,const char * email_token){
    const char * message;
    int res=_change_factor_token_request(session_id,user_name,email_token, & message);
    SSL_write(ssl,message,strlen(message));
    return res;
}
# endif 