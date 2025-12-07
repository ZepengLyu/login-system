# ifndef CLIENT_LOGIN_H
# define CLIENT_LOGIN_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"


/* send login request */

int create_login_request_message(const char * session_id, const char * user_name,const char ** message_pp){
    * message_pp=fill_with_va(LOGIN_REQUEST,2, session_id, user_name);
    return 0;
}
int login_request(SSL *ssl, const char * session_id, const char * user_name){

    const char * message;
    int res=create_login_request_message(session_id,user_name,&message);
    SSL_write(ssl,message,strlen(message));

    return res;
}


/* response challenge */
int get_challenge(const char * buf,size_t buf_size, const char ** challenge_pp){
    const char * session_id;
    const char * user_name;   
  
    int res=get_with_va(buf,buf_size,3,
        &session_id,
        &user_name,
        challenge_pp
    );
    free(session_id);
    free(user_name);
    return res;
}

int created_signed_challenge_message( const char * buf, size_t buf_size, const char * session_id, const char * user_name,EVP_PKEY * pkey, const char ** message_pp)
{
    const char * challenge;
    int get_res=get_challenge(buf,buf_size,&challenge);
    if (get_res){
        fprintf(stderr,"parse challenge feedback gets problem\n");  // case 1: error
        return get_res;
    }
    else{
        // generate signayure 
        const char * signature;                                     // case 2: error 
        int sign_res=sign_message(challenge, &signature, pkey);
        if (sign_res){
            fprintf(stderr,"sign the challenge gets problem\n");
            return sign_res;
        }
        else{
            // get response_request                                 // case 3: success
            * message_pp=fill_with_va(RESPONSE_REQUEST,3,session_id, user_name, signature);
            return 0;
        }
    }
}

int response_challenge(SSL * ssl, const char * buf, size_t buf_size, const char * session_id, const char * user_name,EVP_PKEY * pkey){
    const char * message;
    int res=created_signed_challenge_message(buf, buf_size, session_id, user_name, pkey, &message);
    SSL_write(ssl,message,strlen(message));
    return res;
}


/* get token from token feedback */
int get_token(const char * buf, size_t buf_size, const char ** token_pp){

    const char * session_id;
    const char * user_name;
    const char * res;

    int get_res=get_with_va(buf,buf_size,4,
        & session_id,
        & user_name,
        & res,
        token_pp
    );

    free(session_id);
    free(user_name);
    free(res);

    return get_res;

}


/* log out request*/
int create_quit_request_message(const char * session_id, const char * user_name, const char * token, const char ** message_pp){
    *message_pp=fill_with_va(QUIT_REQUEST,3, session_id, user_name, token);
}
int quit_request(SSL *ssl, const char *session_id, const char * user_name,const char * token)
{
    const char * message;
    int res=create_quit_request_message(session_id, user_name, token, &message);
    SSL_write(ssl,message,strlen(message));
    return 0;
}

# endif