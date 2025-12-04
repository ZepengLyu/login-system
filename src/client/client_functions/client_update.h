# ifndef CLIENT_UPDATE_H
# define CLIENT_UPDATE_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"



// data request
update_request_t * create_update_request(const char * session_id, const char * user_name, const char * data,  const char * token){

    update_request_t * update_request=_create_request(sizeof(update_request_t));

    update_request->session_id=session_id;
    update_request->user_name=user_name;
    update_request->data=data;
    update_request->token=token;
    
    return update_request;
}

const char * create_update_request_message(update_request_t * update_request){
    const char * message;
    message= fill_with_va(UPDATE_REQUEST,4,
        update_request->session_id,
        update_request->user_name,
        update_request->data, 
        update_request->token);
    return message;
}



int _update_request(const char * session_id,const char * user_name, const char * data,const char * token,const char ** message_pp){

    update_request_t * update_request=create_update_request(session_id,user_name,data,token);    

    * message_pp=create_update_request_message(update_request);

    return 0;
   
}

int update_request(SSL *ssl, const char * session_id,const char * user_name,  const char * data,const char * token){

    const char * message;
    int res=_update_request(session_id,user_name, data,token, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}

# endif