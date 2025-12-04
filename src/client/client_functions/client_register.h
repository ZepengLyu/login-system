# ifndef CLIENT_REGISTER_H
# define CLIENT_REGISTER_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"

/* register request */

register_request_t * create_register_request(const char * session_id, const char * user_name, const char * email, const char * pkey){
    register_request_t * register_request= _create_request(sizeof(register_request_t));

    register_request->session_id=session_id;
    register_request->user_name=user_name;
    register_request->email=email;
    register_request->pubkey=pkey;
   
    return register_request;
}

const char * create_register_request_message(register_request_t * register_request){    
    const char * message= fill_with_va( REGISTER_REQUEST,4,
        register_request->session_id,
        register_request->user_name,
        register_request->email,
        register_request->pubkey
       );
    return message;
}

int _register_request(const char * session_id, const char * user_name, const char *email, const char * privatekey_file, const char ** message_pp){   
    
    const char *pubkey; 
    int generate_res=generate_keypair(&pubkey,privatekey_file);     
    if (generate_res)
        return -1; 
    register_request_t * register_request=create_register_request(session_id, user_name, email, pubkey);

    * message_pp=create_register_request_message(register_request);
    return 0;
}

int register_request(SSL * ssl,const char * session_id, const char * user_name, const char *email, const char * privatekey_file){

    const char * message;

    int res=_register_request(session_id, user_name, email, privatekey_file,&message);

    SSL_write_c(ssl,message,strlen(message)+1);

    return res;

}



/* client receive register_permission_feedback */


register_permission_feedback_t * parse_register_permission_feedback(const char * buf,size_t buf_size){

    register_permission_feedback_t * feedback=_create_feedback(sizeof(register_permission_feedback_t));
    get_with_va(buf,buf_size,4,
        &feedback->session_id,
        &feedback->user_name,
        &feedback->res,
        &feedback->message);

    return feedback;
}

int check_register_permission_feedback (register_permission_feedback_t * feedback,const char * session_id, const char * user_name){
    if (memcmp(feedback->session_id,session_id,strlen(session_id))==1){
        free(feedback);
        return 1;
    }
    if (memcmp(feedback->user_name,user_name,strlen(user_name))==1){
        free(feedback);
        return 1;
    }
    return 0;
};

int handle_register_permission_feedback (const char * buf,size_t buf_size,const char * session_id, const char * user_name){
    
    // parse_register_permission_feedback
    register_permission_feedback_t * parsed_feedback=parse_register_permission_feedback(buf, buf_size);

    // check register_permission_feedback
    int check_res=check_register_permission_feedback(parsed_feedback, session_id, user_name);
    if (check_res==0){
        return 0;
    }
    else{
        return 1;
    }
}

int listen_register_permission_feedback(SSL * ssl, const char * session_id, const char * user_name){
    
    char *buf=OPENSSL_zalloc( MESSAGE_BUFFER_MAX_SIZE);
    size_t buf_size;
    
    while (true){
        buf_size=SSL_read_c(ssl,buf,BUFFER_MAX_SIZE);
        char message_type=buf[0];
        if (message_type==REGISTER_PERMISSION_FEEDBACK){
            int permission_res=handle_register_permission_feedback(buf,buf_size,session_id,user_name);
            if (permission_res==0){ //允许注册
                return 0;
            }
                else if (permission_res==1){  //不允许注册
                return 1;
            }
            else{           // 并非本人的 register_permission_feedback
                continue;
            }
        }
        else{
            continue;
        }
    }
}


/* register token request */
register_token_request_t * create_register_token_request(const char * session_id, const char * user_name, const char * token) {
    register_token_request_t * register_token_request = _create_request(sizeof(register_token_request_t));

    register_token_request->session_id = session_id;
    register_token_request->user_name = user_name;
    register_token_request->token = token;

    return register_token_request;
}

const char * create_register_token_request_message(register_token_request_t * register_token_request) {
    const char * message = fill_with_va(REGISTER_TOKEN_REQUEST, 3,
        register_token_request->session_id,
        register_token_request->user_name,
        register_token_request->token
    );
    return message;
}


int _register_token_request(const char * session_id, const char * user_name, const char * token, const char ** message_pp) {
    register_token_request_t * register_token_request = create_register_token_request(session_id, user_name, token);

    * message_pp = create_register_token_request_message(register_token_request);

    return 0;
}

int register_token_request(SSL *ssl,const char * session_id, const char * user_name, const char * token) {
    const char * message;
    int res=_register_token_request(session_id, user_name, token, &message);
    SSL_write_c(ssl, message, strlen(message)+1);
    return res;
}


/* client receive register_result_feedback */
register_result_feedback_t * parse_register_result_feedback(const char * buf, size_t buf_size) {
    register_result_feedback_t * feedback = _create_feedback(sizeof(register_result_feedback_t));
    get_with_va(buf, buf_size, 3, feedback->session_id, feedback->user_name, feedback->res,feedback->message);
    return feedback;
}

int check_register_result_feedback(register_result_feedback_t * feedback,const char * session_id, const char * user_name) {
    if (memcmp(feedback->session_id, session_id, strlen(session_id))) {
        free(feedback);
        return 1;
    }
    if (memcmp(feedback->user_name, user_name, strlen(user_name))) {
        free(feedback);
        return 1;
    }
    return 0;
}

int handle_register_result_feedback(const char * buf, size_t buf_size, const char * session_id, const char * user_name){
    
    // parse_register_result_feedback
    register_result_feedback_t * parsed_feedback=parse_register_result_feedback(buf, buf_size);

    // check challenge
    int check_res=check_register_result_feedback(parsed_feedback, session_id, user_name);
    if (check_res==0){
        return 0;
    }
    else{
        return 1;
    }

}

int listen_register_result_feedback(SSL * ssl, const char * session_id, const char * user_name) {
    char *buf = OPENSSL_zalloc(MESSAGE_BUFFER_MAX_SIZE);
    size_t buf_size; 
    while (true) {
        buf_size=SSL_read_c(ssl,buf,BUFFER_MAX_SIZE);
        char message_type =buf[0];
        if (message_type == REGISTER_RESULT_FEEDBACK) {
            int res=handle_register_result_feedback(buf, buf_size,session_id, user_name);
            if (res==0) {
                return 0;
            }
            else if(res==1){
                return 1;
            } 
            else{
                continue;
            }
        }
        else {
            continue; // 其他类型的消息
        }
    }
}



# endif