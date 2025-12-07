# ifndef CLIENT_QUERY_H
# define CLIENT_QUERY_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"




int create_query_request_message(const char * session_id, const char * user_name, const char * token,const char ** message_pp ){

    * message_pp=fill_with_va(QUERY_REQUEST,3, session_id, user_name,token);

    return 0;
}

int query_request(SSL *ssl, const char * session_id, const char * user_name, const char * token)
{  
    const char * message;
    int res=create_query_request_message(session_id,user_name,token,&message);

    SSL_write(ssl,message,strlen(message));
    return res;
}



# endif