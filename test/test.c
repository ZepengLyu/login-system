#include <openssl/evp.h>
#include <string.h>
#include <mysql.h>
#include "../src/config.h"
#include "../src/common.h"
#include "../src/crypto.h"
#include "../src/server/email.h"
#include "../src/server/database.h"
#include "../src/server/server_functions.h"
#include "../src/server/server_api.h"
#include "../src/client/client_functions.h"
#include "../src/client/client_api.h"

// user data example
const char * client_username="jack"; 
const char * client_email="jack@123.com"; 
const char * client_privatekey_file="./pem/client_private_key.pem";
const char * data="ABC";

// configuration
const unsigned char * session_id; size_t session_id_size=SESSION_ID_SIZE*2;
const unsigned char * token; size_t token_size=TOKEN_SIZE*2;
const unsigned char * change_factor_token; size_t change_factor_token_size=CHANGE_FACTOR_TOKEN_SIZE*2;
MYSQL * my_connection;

// user generate session id
int initialize_session_id(){
    session_id=generate_session_id();
    return 0;
}

// check message deliver and parse normally
int check_deliver_and_parsing(const char * process_name, void * sender_data, void * accepter_data, size_t sender_struct_size){
    size_t ptr_size=sizeof(void *);
    size_t item_size=ptr_size+sizeof(size_t);
    size_t item_num=sender_struct_size/item_size;
    for (int i; i<item_num;i++){
        const unsigned char ** sender_data_pp=(const unsigned char **)( (char *)(sender_data)+i*item_size ); 
        const unsigned char ** accepter_data_pp=(const unsigned char **)( (char *)(accepter_data)+i*item_size ); 
        size_t data_size= *(size_t *)((char *)(sender_data)+i*item_size+ptr_size) ; // 获得 struct 内存放 item 的地址
        if ( memcmp(*sender_data_pp,*accepter_data_pp,data_size)){
            fprintf(stderr, "%s: %s",process_name,"message deliver and parsing fail\n");
            return 1;
        }
    }
    fprintf(stderr, "%s: %s",process_name,"message deliver and parsing success\n");
    return 0;
}

/* temp: deliver and parse normally
int check_register_request(register_request_t * server_register_request, register_request_t * client_register_request){

    if (memcmp(server_register_request->session_id, client_register_request->session_id, client_register_request->session_id_size)){
        goto check_fail;
    }    
    if (memcmp(server_register_request->user_name, client_register_request->user_name, client_register_request->username_size)){
        goto check_fail;
    }
    if (memcmp(server_register_request->email, client_register_request->email, client_register_request->email_size)){
        goto check_fail;
    }
    if (memcmp(server_register_request->pubkey, client_register_request->pubkey, client_register_request->pubkey_size)){
        goto check_fail;
    }
    fprintf(stderr,"register request deliver and parsing normally\n");
    return 0;
 check_fail:
    fprintf(stderr,"register request deliver and parsing gets problem\n");
    return 1;
}

// check update request deliver and parse normalyy
int check_query_request(update_request_t * server_update_request, update_request_t * client_update_request){
    if (memcmp(server_update_request->session_id, client_update_request->session_id, client_update_request->session_id_size)){
        return 1;
    }
    if (memcmp(server_update_request->user_name, client_update_request->user_name, client_update_request->username_size)){
        return 1;
    }
    if (memcmp(server_update_request->data, client_update_request->data, client_update_request->data_size)){
        return 1;
    }
    if (memcmp(server_update_request->token, client_update_request->token, client_update_request->token_size)){
        return 1;
    }
    return 0;
}

*/

// user register test
int register_test(){
    
 /* client */
    // generate key pair
    const char * client_pubkey; size_t client_pubkey_size;   
    generate_keypair(&client_pubkey, &client_pubkey_size, client_privatekey_file);

    // create register request
    register_request_t * client_register_request=create_register_request(session_id, session_id_size,
        client_username, strlen(client_username), client_email, strlen(client_email),
        client_pubkey, client_pubkey_size);
 
    // get register request message
    const char * register_request_message; size_t register_request_message_size;
    create_register_request_message(&register_request_message,&register_request_message_size,client_register_request);
 
 /* server */
    // parse register request message
    register_request_t * server_register_request=parse_register_request(register_request_message, register_request_message_size);
    
    // check register request execution normally
    check_deliver_and_parsing("register request",client_register_request,server_register_request, sizeof(*server_register_request));
    
    // check user_name if registered
    int validate_username_res=validate_username(my_connection,server_register_request->user_name,server_register_request->username_size);
    if (validate_username_res==0){
        fprintf(stderr,"server: validate_username_res success\n");
        // send email to registered email
        const char * email_token = generate_change_factor_token();
        size_t email_token_size=CHANGE_FACTOR_TOKEN_SIZE*2;

        int record_res=record_email_token(my_connection,
            server_register_request->session_id, server_register_request->session_id_size,
            server_register_request->user_name,server_register_request->username_size,
            server_register_request->email,server_register_request->email_size,
            email_token,email_token_size);
        if (record_res==0){
            fprintf(stderr,"server: record_email_token success\n");
        }
        else{
            fprintf(stderr,"server: record_email_token fails\n");
        }

    /* client */
        // assume user receive the email_token
        register_token_request_t *client_register_token_request=create_register_token_request(
            session_id,session_id_size,
            client_username,strlen(client_username),
            email_token,email_token_size);

        const unsigned char *register_token_request_message; size_t register_token_request_message_size;
        create_register_token_request_message(&register_token_request_message,&register_token_request_message_size,client_register_token_request);

    /* server */
        // parse the register token request
        register_token_request_t * server_register_token_request= parse_register_token_request_message(register_token_request_message,register_token_request_message_size);

        int validate_res=validate_email_token(my_connection,
            server_register_token_request->session_id, server_register_token_request->session_id_size,
            server_register_token_request->user_name, server_register_token_request->username_size,
            server_register_token_request->token,server_register_token_request->token_size);
        if (validate_res){
            fprintf(stderr,"server: validate_email_token fail\n");
        }
        else{
            fprintf(stderr,"server: validate_email_token success\n");
            // record user register data to database
            int insert_res=record_register(my_connection,
                server_register_request->user_name,server_register_request->username_size,
                server_register_request->email,server_register_request->email_size,
                server_register_request->pubkey,server_register_request->pubkey_size    
            ); 
            if (insert_res){
                fprintf(stderr,"server: record_register fail\n");
            }   
            else{
                fprintf(stderr,"server: record_register success\n");
            }
        }      
    }
    else{
        fprintf(stderr,"server: validate_username_res fails");
    }
    return 0;
}

int login_test(){

 /* client */

    // create login request
    initialize_session_id();
    login_request_t * client_login_request=create_login_request(session_id, session_id_size, client_username, strlen(client_username));
    
    // get login request message
    const unsigned char * login_request_message; size_t login_request_message_size;
    create_login_request_message(&login_request_message, &login_request_message_size, client_login_request);

 /* server */
    MYSQL * my_connection=connect_database();

    // parse login request message
    login_request_t * server_login_request=parse_login_request(login_request_message, login_request_message_size);  

    // create challenge feedback    
    challenge_feedback_t * server_challenge_feedback=create_challenge_feedback(server_login_request);   

    // get challenge feedback message
    const unsigned char * challenge_feedback_message; size_t challenge_feedback_message_size;
    create_challenge_feedback_message(&challenge_feedback_message, &challenge_feedback_message_size, server_challenge_feedback);
    
    //record challenge feedback
    int database_res=record_login(my_connection, 
        server_challenge_feedback->session_id, server_challenge_feedback->session_id_size,
        server_challenge_feedback->user_name, server_challenge_feedback->username_size,
        server_challenge_feedback->challenge, server_challenge_feedback->challenge_size
    );

 /* client side process */
    // parse challenge feedback message
    challenge_feedback_t * client_challenge_feedback=parse_challenge_feedback(challenge_feedback_message, challenge_feedback_message_size);
    
    // check challenge feedback
    int check_res=check_challenge_feedback(client_challenge_feedback, session_id, session_id_size, client_username, strlen(client_username));
    if (check_res){
        fprintf(stderr,"challenge feedback check fails\n");
    }
    else{
        fprintf(stderr,"challenge feedback check success\n");
    }

    // sign challenge
    const unsigned char * signature;    size_t signature_size;
    EVP_PKEY * pkey;
    import_privatekey(&pkey,client_privatekey_file);
    sign_message(client_challenge_feedback->challenge, client_challenge_feedback->challenge_size, &signature, &signature_size, pkey);

    // create response request
    response_request_t * client_response_request=create_response_request(client_challenge_feedback, signature, signature_size);
    
    // get response request message
    const unsigned char * response_request_message; size_t response_request_message_size;
    create_response_request_message(&response_request_message, &response_request_message_size, client_response_request);

/* server side process */

    // parse response request message
    response_request_t * server_response_request=parse_response_request(response_request_message, response_request_message_size);
    
    record_response(my_connection, 
        server_response_request->session_id, server_response_request->session_id_size,
        server_response_request->user_name, server_response_request->username_size,
        server_response_request->response, server_response_request->response_size);

    // query challenge
    const unsigned char * challenge; size_t challenge_len;
    int query_chal_res=query_challenge(my_connection, 
        server_response_request->session_id,server_response_request->session_id_size,
        server_response_request->user_name,server_response_request->username_size,
        &challenge, &challenge_len);
    
    // query pubkey
    EVP_PKEY * pubkey;
    int query_pkey_res=query_pubkey(my_connection, 
        server_response_request->user_name,server_response_request->username_size
        , &pubkey);
    
    const unsigned char * token_message; size_t token_message_size;

    // validate response
    if (challenge){
        int res= validate_signature(challenge, challenge_len, server_response_request->response, server_response_request->response_size, pubkey);
        
        if (res==0){
            token_feedback_t * token_feedback=create_token_feedback(server_response_request);

            
            create_token_feedback_message(&token_message, &token_message_size, token_feedback);

            int record_token_res=record_token(my_connection, 
                token_feedback->session_id, token_feedback->session_id_size,
                token_feedback->user_name, token_feedback->username_size,
                token_feedback->token, token_feedback->token_size
            );
            token=token_feedback->token;
            
            fprintf(stderr,"login test success");
        }
        else{
            general_feedback_t * general_feedback=create_general_feedback(
                server_response_request->session_id,server_response_request->session_id_size,
                server_response_request->user_name,server_response_request->username_size,
                "invalid response text",strlen("invalid response text"));
            
            const unsigned char * verify_feedback_message; size_t verify_feedback_message_size;
            create_general_feedback_message(&verify_feedback_message,&verify_feedback_message_size,general_feedback);
        }
    }
/* client */
    token_feedback_t *client_token_feedback=parse_token_feedback(token_message,token_message_size);
    int token_check_res=check_token(client_token_feedback,session_id,session_id_size,client_username,strlen(client_username));
    return 0;
}

int query_request_test(){   
/* client */
    query_request_t * client_query_request= create_query_request(session_id,session_id_size,client_username,strlen(client_username),token,token_size);
    
    const unsigned char *query_message; size_t query_message_size;
    create_query_request_message(&query_message,&query_message_size,client_query_request);
/* server */
    query_request_t *server_query_request= parse_query_request(query_message,query_message_size);
    int check_query_request_res=check_deliver_and_parsing("query request",client_query_request,server_query_request,sizeof(*client_query_request));

    int validate_token_res=validate_token(my_connection,
         server_query_request->session_id, server_query_request->session_id_size, 
         server_query_request->user_name, server_query_request->username_size,
         server_query_request->token,server_query_request->token_size);

    const char *data;
    size_t data_size=0;
    int query_data_res=query_data(my_connection,
        server_query_request->user_name,server_query_request->username_size,
        &data,&data_size
    );

    const unsigned char * data_message;
    size_t data_message_size;
    if (data_size!=0){
        general_feedback_t* general_feedback =create_general_feedback(
            server_query_request->session_id,server_query_request->session_id_size,
            server_query_request->user_name,server_query_request->username_size,
            data,data_size
        );

        create_general_feedback_message(&data_message,&data_message_size,general_feedback);
    }
    else{
        data_message=" ";
        data_message_size=1;

        general_feedback_t* general_feedback =create_general_feedback(
            server_query_request->session_id,server_query_request->session_id_size,
            server_query_request->user_name,server_query_request->username_size,
            data_message,data_message_size
        );

        create_general_feedback_message(&data_message,&data_message_size,general_feedback);

    }
}

int update_request_test(){
 /* client */
    update_request_t * client_update_request= create_update_request(
        session_id,session_id_size,
        client_username,strlen(client_username),
        data,strlen(data),
        token,token_size);
    
    const unsigned char *update_message; size_t update_message_size;

    create_update_request_message(&update_message,&update_message_size,client_update_request);
 /* server */
    MYSQL * my_connection=connect_database();
    update_request_t *server_update_request= parse_update_request(update_message,update_message_size);
    int check_query_request_res=check_deliver_and_parsing("update request",client_update_request,server_update_request,sizeof(*client_update_request));

    int validate_token_res=validate_token(my_connection,
         server_update_request->session_id, server_update_request->session_id_size, 
         server_update_request->user_name, server_update_request->username_size,
         server_update_request->token,server_update_request->token_size);

        
    if (validate_token_res==0){
        int update_res=update_data(my_connection,
        server_update_request->user_name,server_update_request->username_size,
        server_update_request->data,server_update_request->data_size);

        if(update_res==0){
            
            general_feedback_t* general_feedback =create_general_feedback(
                server_update_request->session_id,server_update_request->session_id_size,
                server_update_request->user_name,server_update_request->username_size,
                "update data successfully",strlen("update data successfully"));
            
            
            const unsigned char *update_request_response_message;
            size_t update_request_response_message_size;

            create_general_feedback_message(&update_request_response_message,&update_request_response_message_size,general_feedback);

        }
    }
    return 0;
}

int change_factor_test(){
 /* client */
    change_factor_request_t * client_change_factor_request= create_change_factor_request(
        session_id,session_id_size,
        client_username,strlen(client_username));
    
    const unsigned char *change_factor_request_message; size_t change_factor_request_message_size;
    create_query_request_message(&change_factor_request_message,&change_factor_request_message_size,client_change_factor_request);

 /* server */
    change_factor_request_t * server_change_factor_request= parse_change_factor_request(
        change_factor_request_message,change_factor_request_message_size);
    
    // check message delivery and parsing

    // query email as the recipient
    const char * email; size_t email_size;
    int query_email_res=query_email(my_connection, 
        server_change_factor_request->user_name, server_change_factor_request->username_size,
        &email, &email_size);

    // generate change-factor token
    const unsigned char * change_factor_token = generate_change_factor_token();
    size_t change_factor_token_size=CHANGE_FACTOR_TOKEN_SIZE;

    // record change-factor token into database
    record_change_factor_token(my_connection,
        server_change_factor_request->session_id,server_change_factor_request->session_id_size,
        server_change_factor_request->user_name,server_change_factor_request->username_size,
        change_factor_token, change_factor_token_size);

    // send email to user
    // send_email(email, change_factor_token, token_size);
 
 /* client */

    // generate key pair
    const unsigned char * new_pubkey; size_t new_pubkey_size;   
    generate_keypair(&new_pubkey, &new_pubkey_size, client_privatekey_file);

    change_factor_token_request_t * client_change_factor_token_request= create_change_factor_token_request(
        session_id, session_id_size,
        client_username,strlen(client_username),
        new_pubkey,new_pubkey_size,
        change_factor_token, change_factor_token_size);

    const unsigned char *change_factor_token_request_message; size_t change_factor_token_request_message_size;
    create_change_factor_token_request_message(
        &change_factor_token_request_message, &change_factor_token_request_message_size,
        client_change_factor_token_request);

 /* server */
    change_factor_token_request_t * server_change_factor_token_request=parse_change_factor_token_request(
        change_factor_token_request_message,change_factor_token_request_message_size );
    
    int validate_res=validate_change_factor_token(my_connection,
        server_change_factor_token_request->session_id, server_change_factor_token_request->session_id_size,
        server_change_factor_token_request->user_name, server_change_factor_token_request->username_size,
        server_change_factor_token_request->token, server_change_factor_token_request->token_size
    );

    int update_res=update_pubkey(my_connection,
        server_change_factor_token_request->user_name, server_change_factor_token_request->username_size,
        server_change_factor_token_request->new_pubkey, server_change_factor_token_request->new_pubkey_size
    );
    return 0;
}

// int ssl_test(){
// }

// int system_integration_test(){
// }


int main(){

    // initialize configurattion
    my_connection=connect_database(); 
    session_id=generate_session_id(); 
    
    register_test();
    login_test();
    query_request_test();
    // update_request_test();
    // change_factor_test();
    
    return 0;
}
