
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

int create_change_factor_request_message(const char * session_id, const char * user_name,const char ** message_pp){
    
    *message_pp=fill_with_va(CHANGE_FACTOR_REQUEST,2, session_id,user_name);
    return 0;
}

int change_factor_request(SSL *ssl, const char * session_id, const char * user_name){
    const char * message;
    create_change_factor_request_message(session_id,user_name,&message);
    SSL_write(ssl,message,strlen(message));
    return 0;
}
/* round 2*/

int create_change_factor_token_request_message(const char * session_id, const char * user_name,const char * email_token,const char ** message_pp){

    const char *new_pubkey;
    int generate_res=generate_keypair(&new_pubkey,CLIENT_PRIVATEKEY_FILE);

    * message_pp=fill_with_va(CHANGE_FACTOR_TOKEN_REQUEST,4, session_id, user_name,new_pubkey, email_token);
    return 0;
}

int change_factor_token_request(SSL *ssl,const char * session_id, const char * user_name,const char * email_token){
    const char * message;
    int res=create_change_factor_token_request_message(session_id,user_name,email_token, & message);
    SSL_write(ssl,message,strlen(message));
    return res;
}
# endif 