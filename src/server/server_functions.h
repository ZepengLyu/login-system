# ifndef SERVER_FUNCTIONS_H
# define SERVER_FUNCTIONS_H
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <mysql.h>
#include <err.h>
#include <openssl/err.h>
#include "./database.h"
#include "../config.h"
#include "../common.h"
#include "../message_type.h"
#include "../crypto.h"

// general feedback 
general_feedback_t * create_general_feedback(const unsigned char * session_id, size_t session_id_size, 
    const char *user_name, size_t user_name_size, 
    const char * message, size_t message_size){
    
    general_feedback_t * general_feedback=_create_general_feedback();

    general_feedback->session_id=session_id;
    general_feedback->session_id_size=session_id_size;
    
    general_feedback->user_name=user_name;
    general_feedback->username_size=user_name_size;
    
    general_feedback->message=message;
    general_feedback->message_size=message_size;
    
    return general_feedback;
}

int create_general_feedback_message(const unsigned char ** text_pp, size_t * text_len_p, general_feedback_t* feedback_data)
{
    fill_with_va(text_pp, text_len_p, FEEDBACK_TYPE,3,
        feedback_data->session_id,feedback_data->session_id_size,
        (const unsigned char *) feedback_data->user_name, feedback_data->username_size, 
        (const unsigned char *) feedback_data->message, feedback_data->message_size);
    return 0;
}







# endif