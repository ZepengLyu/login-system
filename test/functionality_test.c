#include <openssl/evp.h>
#include <string.h>
#include <mysql.h>
#include "../src/config.h"
#include "../src/common.h"
#include "../src/crypto.h"
#include "../src/server/server_api.h"
#include "../src/client/client_api.h"
#include <unistd.h>

// user data example
const char * user_name="jack"; 
const char * email="jack@123.com"; 
const char * privatekey_file="./src/client/pem/client_private_key.pem";
const char * data="ABC";

// configuration
const char * session_id; 
const char * token; 
const char * change_factor_token; 
MYSQL * my_connection;


// // user register test
// int register_test(MYSQL * my_connection, const char * session_id){

//     const char * client_message;
//     int res;
//     /* client */
//     res=_register_request(session_id, user_name, email, privatekey_file,&client_message);
//     if (res)
//         exit(1);

//     /* server */
//     const char * server_message;
//     const char * email_token;
//     res=_register_request_callback(my_connection,client_message,strlen(client_message),&server_message,&email_token);
//     if (res)  return 1;
   
//     /* client */
//     res=handle_register_permission_feedback(server_message,strlen(server_message),session_id,user_name);

//     free(client_message);
//     res=_register_token_request(session_id, user_name, email_token, &client_message);

//     /* server */
//     free(server_message);
//     res=_register_token_request_callback(my_connection,client_message,strlen(client_message)+1,&server_message);

//     return 0;
// }

int login_test(MYSQL * my_connection, const char * session_id,const char ** token_pp){
    /* client */
    const char * client_message;
    int client_res=_login_request(session_id, user_name,&client_message);
    if (client_res) exit(1);
    
    /* server */
    const char * server_message;
    int server_res=_login_request_callback(my_connection,client_message,strlen(client_message),&server_message);

    /* client */
    EVP_PKEY * pkey;
    int import_res=import_privatekey(&pkey,CLIENT_PRIVATEKEY_FILE);
    if (import_res) return 1;

    free(client_message);
    client_res= _response_challenge(server_message , strlen(server_message), session_id,user_name, pkey, & client_message);

    /* server */
    free(server_message);
    server_res=_response_request_callback(my_connection,client_message,strlen(client_message),& server_message);

    /* client */

    int handle_token_res=handle_token(server_message, strlen(server_message),session_id,user_name,token_pp);
    return 0;
}

int query_request_test(MYSQL * my_connection, const char * session_id, const char * token){
    /* client */
    const char * client_message;
    int res=_query_request(session_id, user_name,token,& client_message);

    const char * server_message;
    int server_res=_query_request_callback(my_connection,client_message,strlen(client_message),&server_message);
    return res;
}

int update_request_test(MYSQL * my_connection, const char * session_id, const char * token){
   
    /* client */
    const char * new_data="abcd";

    const char * client_message;
    int client_res=_update_request(session_id, user_name,token,new_data,& client_message);
    if (client_res){ 
        return 1;
    }
    const char * server_message;
    int server_res=_update_request_callback(my_connection,client_message,strlen(client_message),&server_message);
    if (server_res){
        return 1;
    }
    return 0;
}

int change_factor_test(MYSQL * my_connection, const char * session_id){

    const char * client_message;
    const char * server_message;
    int client_res;
    int server_res;
    const char * email_token;

    client_res=_change_factor_request(session_id, user_name,& client_message);
    if (client_res) 
        return client_res;
    
    server_res=_change_factor_request_callback(my_connection,client_message,strlen(client_message),&server_message,&email_token);
    if (server_res) 
        return server_res;

    free(client_message);
    client_res=_change_factor_token_request(session_id, user_name,email_token, & client_message);
    if (client_res) 
        return client_res;

    free(server_message);
    server_res=_change_factor_token_request_callback(my_connection,client_message,strlen(client_message),& server_message);
    if (server_res) 
    return server_res;

    return 0;
}

int main(){

    // initialize configuration
    my_connection=connect_database(); 
    session_id=generate_session_id(); 
   
    // int register_res=register_test(my_connection,session_id);
    // const char * token;
    // int login_res=login_test(my_connection,session_id,&token);

    // query_request_test(my_connection,session_id,token);
    // update_request_test(my_connection,session_id,token);

    change_factor_test(my_connection,session_id);
    
    return 0;
}
