#ifndef MESSAGE_TYPE_H
#define MESSAGE_TYPE_H
#include <stdlib.h>

# define REGISTER_REQUEST '0'
# define REGISTER_PERMISSION_FEEDBACK '1'
# define REGISTER_TOKEN_REQUEST '2'
# define REGISTER_RESULT_FEEDBACK '3'

# define LOGIN_REQUEST '4'
# define CHALLENGE_FEEDBACK '5'
# define RESPONSE_REQUEST '6'
# define TOKEN_FEEDBACK '7'

# define QUERY_REQUEST '8'
# define UPDATE_REQUEST '9'
# define RESULT_FEEDBACK 'A'
# define QUIT_REQUEST 'B'
# define QUIT_FEEDBACK 'C'

# define CHANGE_FACTOR_REQUEST 'D'
# define CHANGE_FACTOR_FEEDBACK 'E'
# define CHANGE_FACTOR_TOKEN_REQUEST 'F'
# define CHANGE_FACTOR_TOKEN_FEEDBACK 'G'

/* register */
typedef struct{
    const char * session_id;
    const char * user_name;  
    const char * email;  
    const char * pubkey; 
} register_request_t;

typedef struct{
    const char * session_id;
    const char * user_name;  
    const char * res;  
    const char * message; 
} register_permission_feedback_t;


typedef struct{
    const char * session_id; 
    const char * user_name; 
    const char * token; 
} register_token_request_t; 


typedef struct{
    const char * session_id;
    const char * user_name;  
    const char * res;  
    const char * message; 
} register_result_feedback_t;


/* register */

/* login */
typedef struct{
    const char * session_id; 
    const char * user_name;  
} login_request_t;

typedef struct{
    const char * session_id;
    const char * user_name;  
    const char * res;
    const char * challenge; 
} challenge_feedback_t;

typedef struct{
    const char * session_id; 
    const char * user_name;  
    const char * response; 
} response_request_t;

typedef struct{
    const char * session_id; 
    const char * user_name;  
    const char * res;  
    const char * token; 
} token_feedback_t;
/* login */


typedef struct{
    const char * session_id; 
    const char * user_name;  
    const char * message;  
} general_feedback_t;

typedef struct{
    const char * session_id;
    const char * user_name; 
} change_factor_request_t;

typedef struct{
    const char * session_id;
    const char * user_name;  
    const char * new_pubkey; 
    const char * token; 
} change_factor_token_request_t;

typedef struct{
    const char * session_id;
    const char * user_name;
    const char * res;
    const char * data; 
} change_factor_feedback_t;

typedef struct{
    const char * session_id;
    const char * user_name;
    const char * res;
    const char * data; 
} change_factor_token_feedback_t;


typedef struct{
    const char * session_id; 
    const char * user_name; 
    const char * data; 
    const char * token; 
} update_request_t;

typedef struct{
    const char * session_id; 
    const char * user_name;  
    const char * token; 
} query_request_t;


typedef struct{
    const char * session_id; 
    const char * user_name;  
    const char * res;
    const char * data; 
} result_feedback_t;

void* _create_request(size_t size) {
    void* request = malloc(size);
    if (request) {
        memset(request, 0, size);
    }
    return request;
}

void* _create_feedback(size_t size) {
    void* feedback = malloc(size);
    if (feedback) {
        memset(feedback, 0, size);
    }
    return feedback;
}

#endif