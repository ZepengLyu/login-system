# ifndef SERVER_COMMON_H
# define SERVER_COMMON_H
# include "./server_database.h"
# include "./server_email.h"
# include "../../message_type.h"
# include "../../common.h"


result_feedback_t * create_result_feedback(const char * session_id, const char * user_name, const char * res, const char * data){
    result_feedback_t * feedback=(result_feedback_t *)_create_request(sizeof(result_feedback_t));
    feedback->session_id=session_id;
    feedback->user_name=user_name;
    feedback->res=res;
    feedback->data=data;
    return feedback;
}
const char * create_result_feedback_message(result_feedback_t * feedback){
    const char * message;
    message=fill_with_va( RESULT_FEEDBACK,4,
        feedback->session_id,
        feedback->user_name,
        feedback->res,
        feedback->data);
    return message;
}
# endif