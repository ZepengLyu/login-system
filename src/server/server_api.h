# ifndef SERVER_API_H
# define SERVER_API_H

# include "./server_functions/server_register.h"
# include "./server_functions/server_login.h"
# include "./server_functions/server_query.h"
# include "./server_functions/server_update.h"
# include "./server_functions/server_change_factor.h"
# include <unistd.h>

// int feedback_to_client(SSL * ssl,
//     const unsigned char * session_id, size_t session_id_size, 
//     const char *user_name, size_t user_name_size, 
//     const char * message_content, size_t message_content_size){
    
//     general_feedback_t * general_feedback=create_general_feedback(session_id,session_id_size,user_name,user_name_size,message_content,message_content_size);

//     const unsigned char * message;    size_t message_size;
//     create_general_feedback_message(&message,&message_size,general_feedback);
    
//     SSL_write(ssl,message,message_size);
//     return 0;
// }


int server_listen (SSL * ssl, MYSQL * my_connection){

    /* cache */
    const char * buf = OPENSSL_zalloc(MESSAGE_BUFFER_MAX_SIZE+1);
    size_t buf_size;    

    while (true){
        buf_size=SSL_read(ssl,buf,MESSAGE_BUFFER_MAX_SIZE);
        if (buf_size==0){
            continue;
        }
        char message_type=buf[0];

        switch(message_type){
            case REGISTER_REQUEST:
                register_request_callback(ssl,my_connection,buf,buf_size);
                break;
            case REGISTER_TOKEN_REQUEST:
                register_token_request_callback(ssl,my_connection,buf,buf_size);
                break;
            // case LOGIN_REQUEST:
            //     login_request_callback(ssl,my_connection,buf,buf_size);
            //     break;
            // case RESPONSE_REQUEST:
            //     response_request_callback(ssl,my_connection,buf,buf_size);
            // case QUERY_REQUEST:
            //     query_request_callback(ssl,my_connection,buf,buf_size);
            //     break;
            // case UPDATE_REQUEST:
            //     update_request_callback(ssl,my_connection,buf,buf_size);
            //     break;
            // case CHANGE_FACTOR_REQUEST:
            //     change_factor_request_callback(ssl,my_connection,buf,buf_size);
            //     break;
            // case CHANGE_FACTOR_TOKEN_REQUEST:
            //     change_factor_token_request_callback(ssl,my_connection,buf,buf_size);
            //     break;
            // default:
                
        }
    }
    return 0;
}

# endif
