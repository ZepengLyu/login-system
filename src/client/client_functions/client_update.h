# ifndef CLIENT_UPDATE_H
# define CLIENT_UPDATE_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"



int create_update_request_message(const char * session_id,const char * user_name, const char * data,const char * token,const char ** message_pp){

    * message_pp=fill_with_va(UPDATE_REQUEST,4, session_id, user_name, data, token);
    return 0;
}

int update_request(SSL *ssl, const char * session_id,const char * user_name,  const char * data,const char * token){

    const char * message;
    int res=create_update_request_message(session_id,user_name, data,token, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}

# endif