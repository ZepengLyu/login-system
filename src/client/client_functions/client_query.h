# ifndef CLIENT_QUERY_H
# define CLIENT_QUERY_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"



query_request_t * create_query_request(const char * session_id, const char * user_name, const unsigned char * token){
    
    query_request_t * query_request=_create_request(sizeof(query_request_t));
    query_request->session_id=session_id;
    query_request->user_name=user_name;
    query_request->token=token;
    return query_request;
}

const char * create_query_request_message(query_request_t * query_request){
    
    const char * message;
    message=fill_with_va(QUERY_REQUEST,3,
        query_request->session_id, 
        query_request->user_name, 
        query_request->token
       );
    return message;
}


int _query_request(const char * session_id, const char * user_name, const char * token,const char ** message_pp ){

    query_request_t * query_request=create_query_request(session_id, user_name, token);    

    * message_pp=create_query_request_message(query_request);

    return 0;
}

int query_request(SSL *ssl, const char * session_id, const char * user_name, const char * token)
{  
    const char * message;
    int res=_query_request(session_id,user_name,token,&message);

    SSL_write(ssl,message,strlen(message));
    return res;
}



# endif