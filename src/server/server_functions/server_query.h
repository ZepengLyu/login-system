# ifndef SERVER_QUERY_H
# define SERVER_QUERY_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "../../config.h"
#include "./server_common.h"
#include "../../crypto.h"

query_request_t * parse_query_request(const char * buf, size_t buf_size)
{
    query_request_t * query_request=_create_request(sizeof(query_request_t));
    get_with_va(buf,buf_size,3,
        &query_request->session_id,
        &query_request->user_name,
        &query_request->token
    );
    return query_request;
}

int _query_request_callback(MYSQL * my_connection, const  char * buf, size_t buf_size, const char ** message_pp){
    
    query_request_t * query_request = parse_query_request(buf,buf_size);

    int validate_res=validate_token(my_connection,
        query_request->session_id, 
        query_request->user_name,
        query_request->token);

    if (validate_res){ // invalid token
        result_feedback_t * result_feedback=create_result_feedback(query_request->session_id,query_request->user_name,"1","invalid token");
        * message_pp=create_result_feedback_message(result_feedback);
    }
    else{ // valid token
        char * data; 
        int query_res=query_data(my_connection,query_request->user_name,&data);

        result_feedback_t * result_feedback=create_result_feedback(query_request->session_id,query_request->user_name,"0",data);
        * message_pp=create_result_feedback_message(result_feedback);
    }
}
int query_request_callback(SSL *ssl, MYSQL * my_connection, const  char * buf, size_t buf_size){
    const char * message;
    int res=_query_request_callback(my_connection, buf, buf_size, &message);
    SSL_write(ssl, message, strlen(message));
    return res; 
}


# endif 