# ifndef CLIENT_LOGIN_H
# define CLIENT_LOGIN_H
# include <openssl/evp.h>
# include <openssl/core_names.h>
# include <string.h>
# include "../../config.h"
# include "../../common.h"
# include "../../message_type.h"
# include "../../crypto.h"


/* login request */
login_request_t * create_login_request(const char * session_id,const char *user_name){

    login_request_t* login_request=_create_request(sizeof(login_request_t)); 

    login_request->session_id=session_id;
    login_request->user_name=user_name;
    
    return login_request;
}

const char * create_login_request_message(login_request_t * login_request){
    
    const char * message;
    message=fill_with_va(LOGIN_REQUEST,2,
        login_request->session_id,
        login_request->user_name);
    return message;
}

int _login_request(const char * session_id, const char * user_name,const char ** message_pp)
{   
    login_request_t * login_request=create_login_request(session_id, user_name);

    * message_pp= create_login_request_message(login_request);

  
    return 0;
}

int login_request(SSL *ssl, const char * session_id, const char * user_name){
    const char * message;
    int res=_login_request( session_id, user_name, &message);
    SSL_write(ssl,message,strlen(message+1));
    return res;
}


/* response request */

challenge_feedback_t * parse_challenge_feedback(const char * buf, size_t buf_size){

    challenge_feedback_t * feedback=_create_feedback(sizeof(challenge_feedback_t));
    get_with_va(buf,buf_size,3,
        &feedback->session_id,
        &feedback->user_name,
        &feedback->challenge
    );
    return feedback;
}

int check_challenge(challenge_feedback_t *client_challenge_feedback, const char * session_id, const char * user_name)
{   
    if (memcmp(client_challenge_feedback->session_id,session_id,strlen(session_id))){
        return 1;
    };
    if (memcmp(client_challenge_feedback->user_name,user_name,strlen(user_name))){
        return 1;
    }
    return 0;
}

int handle_challenge(const char * buf,size_t buf_size, const char * session_id, const char * user_name, const char ** challenge_pp){
    // parse_chanllege_feedback
    challenge_feedback_t * parsed_feedback=parse_challenge_feedback(buf, buf_size);

    // check challenge
    int check_res=check_challenge(parsed_feedback, session_id, user_name);
    if (check_res==0){
        * challenge_pp=parsed_feedback->challenge;
        return 0;
    }
    else{
        * challenge_pp=NULL;
        return 1;
    }
}

// int listen_challenge(SSL *ssl ,const char * session_id, const char * user_name, const char ** ret_challenge_pp){
//     char *buf=OPENSSL_zalloc( MESSAGE_BUFFER_MAX_SIZE);
//     size_t buf_size;

//     while (true){
//         buf_size=SSL_read(ssl,buf,BUFFER_MAX_SIZE);
//         char feedback_type=buf[0];

//         if (feedback_type==CHALLENGE_FEEDBACK){
//             if (handle_challenge(buf,buf_size,session_id,user_name,ret_challenge_pp)==0){ 
//                 return 0;
//             }
//             else{
//                 continue; // 其他人的反馈
//             }
//         }
//         else  // 其他类型的消息
//             continue; 
//         }
// };


response_request_t * create_response_request(const char *session_id,const char * user_name, const char * signature){
    
    response_request_t * response_request=_create_request(sizeof(response_request_t));

    response_request->session_id= session_id;
    response_request->user_name= user_name;
    response_request->response= signature;
    return response_request;
}

const char * create_response_request_message(response_request_t * response_request){
    
    const char * message;
    message=fill_with_va(RESPONSE_REQUEST,3,
        response_request->session_id, 
        (const unsigned char *) response_request->user_name, 
        response_request->response);
    return message;
}

int _response_challenge( const char * buf, size_t buf_size, const char * session_id, const char * user_name,EVP_PKEY * pkey, const char ** message_pp)
{
    const char * challenge;
    int handle_res=handle_challenge(buf,buf_size,session_id,user_name,&challenge);
    
    if (handle_res){
        fprintf(stderr,"handle challenge feedback gets problem\n");
        return 1;
    }
    
    // sign challenge
    const char * signature;    
    int sign_res=sign_message(challenge, &signature, pkey);
    
    // get response_request

    response_request_t * response_request=create_response_request(session_id,user_name,signature);

    // get response_text
    * message_pp=create_response_request_message(response_request);

    return 0;
}

int response_challenge(SSL * ssl, const char * buf, size_t buf_size, const char * session_id, const char * user_name,EVP_PKEY * pkey){
    const char * message;
    int res=_response_challenge(buf, buf_size, session_id, user_name, pkey, &message);
    SSL_write(ssl,message,strlen(message)+1);
    return res;
}
/* response request */


/* get token */
token_feedback_t * parse_token_feedback(const char * buf, size_t buf_size){

    token_feedback_t * token_feedback=_create_feedback(sizeof( token_feedback_t));

    get_with_va(buf,buf_size,4,
        &token_feedback->session_id, 
        &token_feedback->user_name, 
        &token_feedback->res, 
        &token_feedback->token
    );

    return token_feedback;
}

int check_token(token_feedback_t *token_feedback, const char * session_id, const char * user_name){
     
    if (memcmp(token_feedback->session_id,session_id,strlen(session_id))){
        return 1;
    }
    if (memcmp(token_feedback->user_name,user_name,strlen(user_name))){
        return 1;
    }
    return 0;
}

int handle_token(const char * buf, size_t buf_size,
   const char * session_id, const char * user_name,  
   const char ** token_pp){

    token_feedback_t * token_feedback = parse_token_feedback(buf, buf_size);

    int check_res=check_token(token_feedback, session_id, user_name);
    if (check_res!=0){
        fprintf(stderr,"token feedback check fails");
        return 1;
    }

    *token_pp=token_feedback->token;
    return 0;
}

// int listen_token(SSL *ssl ,const char * session_id, const char * user_name, const char ** ret_token_pp){

//     char *buf=OPENSSL_zalloc( MESSAGE_BUFFER_MAX_SIZE);
//     size_t buf_size;

//     while (true){
//         buf_size=SSL_read(ssl,buf,BUFFER_MAX_SIZE);
//         char feedback_type=buf[0];

//         if (feedback_type==TOKEN_FEEDBACK){
            
//             if (handle_token(buf,buf_size,session_id,user_name,ret_token_pp)==0){ 
//                 return 0;
//             }
//             else{
//                 continue; // 其他人的反馈
//             }
//         }
//         else  // 其他类型的消息
//             continue; 
//         }


// };
# endif