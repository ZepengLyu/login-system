# ifndef SERVER_UPDATE_H
# define SERVER_UPDATE_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "./server_common.h"
#include "../../config.h"
#include "../../crypto.h"


update_request_t *  parse_update_request(const char * buf, size_t buf_size)
{   
    update_request_t * update_request=_create_request(sizeof(update_request_t));
    get_with_va(buf,buf_size,4,
        &update_request->session_id, 
        &update_request->user_name,
        &update_request->data,
        &update_request->token
    );
    return update_request;
}


int _update_request_callback(MYSQL * my_connection, const char * buf, size_t buf_size, const char ** message_pp){
 
    update_request_t * update_request=parse_update_request(buf,buf_size);

    int res=validate_token(my_connection,
        update_request->session_id,
        update_request->user_name,
        update_request->token);

    if (res==-1){ // server 无法进行验证
        result_feedback_t * result_feedback=create_result_feedback(update_request->session_id,update_request->user_name,"1","server gets problem");
        * message_pp=create_result_feedback_message(result_feedback);
        return -1;
    }
    if (res==1){ // invalid token
        result_feedback_t * result_feedback=create_result_feedback(update_request->session_id,update_request->user_name,"1","invalid token");
        * message_pp=create_result_feedback_message(result_feedback);
        return 1;
    }
    else{ // valid token
        int res=update_data(my_connection,update_request->user_name,update_request->data);
        if (res){
            result_feedback_t * result_feedback=create_result_feedback(update_request->session_id,update_request->user_name,"1","server update fail");
            * message_pp=create_result_feedback_message(result_feedback);
            return 1;
        }
        else{
            result_feedback_t * result_feedback=create_result_feedback(update_request->session_id,update_request->user_name,"0","update success");
            * message_pp=create_result_feedback_message(result_feedback);
            return 0;
        }
    }
    

}
int update_request_callback(SSL *ssl, MYSQL * my_connection, const char * buf, size_t buf_size){

    const char * message;
    int res=_update_request_callback(my_connection, buf, buf_size, &message);
    SSL_write(ssl,message,strlen(message));
    return res;
}

# endif