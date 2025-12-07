# ifndef DATABASE_H
# define DATABASE_H

#include <mysql.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "../../message_type.h"
#include "../../config.h"
#include "../../common.h"

MYSQL * connect_database(){
    MYSQL * my_connection=mysql_init(NULL);
    if (my_connection==NULL){
        fprintf(stderr,"mysql_init fails");
        return NULL;
    }
    if (mysql_real_connect(my_connection, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, CLIENT_FOUND_ROWS)==NULL){
        fprintf(stderr,"mysql_real_connect fails");
        mysql_close(my_connection);
        return NULL;
    }
    if (mysql_set_character_set(my_connection, "ascii")) {
        fprintf(stderr, "mysql_set_character_set fails: %s\n", mysql_error(my_connection));
        mysql_close(my_connection);
        return NULL;
    }
    return my_connection;
}

//   提供的 SQL 语句应该确保 result 是最新的一条;
//   可变参数格式与 update_datebase 一致，除了最后一个参数接收 result
int _query_database(MYSQL * my_connection, char * sql,size_t counts,...){

    MYSQL_BIND param_bind[counts-1]; 
    memset(param_bind, 0, sizeof(param_bind));
    MYSQL_BIND result_bind[1];
    memset(result_bind, 0, sizeof(result_bind));

    // initialize stmt
    MYSQL_STMT *stmt;
    stmt = mysql_stmt_init(my_connection);
    if (stmt==NULL){                                                   
        fprintf(stderr, "mysql_stmt_init gets problem\n"); 
        goto error_callback;
    }
    if (mysql_stmt_prepare(stmt, sql, strlen(sql))){
        fprintf(stderr, "mysql_stmt_prepare gets problem\n"); 
        goto error_callback;
    };
    
    // bind input
    
    bool is_null=0;
    va_list args;
    va_start(args, counts);
    for (int i = 0; i < counts-1; i++) {
        void * data = va_arg(args,void *);
        size_t * data_size_p = va_arg(args, size_t*);
        enum_field_types data_type=va_arg(args,enum_field_types);
        
        param_bind[i].is_null = &is_null;
        param_bind[i].buffer_type = data_type;
        param_bind[i].buffer =  data;
        param_bind[i].length = data_size_p;
        // param_bind[i].buffer_length = *data_size_p;
    }
    if (mysql_stmt_bind_param(stmt, param_bind)) {
        fprintf(stderr, "mysql_stmt_bind_param fails\n");
        goto error_callback;
    }
    
    // execute
    if (mysql_stmt_execute(stmt)) {                        
        fprintf(stderr, "mysql_stmt_execute fails\n");
        goto error_callback;
    }

    // bind result
   
    void * result_data = va_arg(args,void *);
    size_t * result_data_size_p = va_arg(args, size_t *);
    enum_field_types result_data_type=va_arg(args,enum_field_types);
    va_end(args);

    result_bind[0].buffer_type = result_data_type;
    result_bind[0].buffer =  result_data;
    result_bind[0].length = result_data_size_p;
    result_bind[0].buffer_length =  RESULT_BUFFER_MAX_SIZE;
    if (mysql_stmt_bind_result(stmt, result_bind)) {       
        fprintf(stderr, "mysql_stmt_bind_result fails\n");
        goto error_callback;
    }
    if (mysql_stmt_store_result(stmt)) {                   
        fprintf(stderr, "mysql_stmt_store_result fails\n");
        goto error_callback;
    }

    size_t row_count = mysql_stmt_num_rows(stmt);
    if (row_count==0){                                      // case: success, return 1
        fprintf(stderr,"Query success but not result\n");
        mysql_stmt_close(stmt);
        return 1;
    }
    else{
        if (mysql_stmt_fetch(stmt)) {                       
            fprintf(stderr, "mysql_stmt_fetch falls \n");
            goto error_callback;
        }
        else{                                                // case: success, return 0
            fprintf(stderr,"Query success\n");
            mysql_stmt_close(stmt);
            return 0;                                      
        }
    }

error_callback:
    fprintf(stderr, mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
}

//   可变参数格式: (void *)data, (size_t *) data_size, data_type, 例如 user_name, username_size, MYSQL_TYPE_STRING
//   这里 data 与 data_size 需要是持久化指针，否则会出现 insert 数据长度的错误
int _update_database(MYSQL * my_connection, char *sql,size_t counts,...){
    MYSQL_BIND param_bind[counts];
    memset(param_bind, 0, sizeof(param_bind));

    // initialize stmt
    MYSQL_STMT *stmt;   
    stmt = mysql_stmt_init(my_connection);
    if (stmt==NULL){
        fprintf(stderr, "mysql_stmt_init fails %s\n");
        goto error_callback;
    }
    if (mysql_stmt_prepare(stmt, sql, strlen(sql))){
        fprintf(stderr, "mysql_stmt_prepare fails\n");
        goto error_callback;
    };

    // bind input
    bool is_null=0;
    va_list args;
    va_start(args, counts);
    for (int i = 0; i < counts; i++) {
        void * data = va_arg(args, void *);
        size_t * data_size_p = va_arg(args, size_t*);
        enum_field_types data_type=va_arg(args,enum_field_types);
        
        param_bind[i].is_null = &is_null;             // not null
        param_bind[i].buffer_type = data_type;
        param_bind[i].buffer = data;
        param_bind[i].length = data_size_p;
        // param_bind[i].buffer_length= *data_size_p;
    }
    if (mysql_stmt_bind_param(stmt, param_bind)) {
        fprintf(stderr, "mysql_stmt_bind_param fails\n");
        goto error_callback;
    }

    // execute
    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "mysql_stmt_execute fails\n");
        goto error_callback;
    }
    else{
        return 0;
    }
   
error_callback:
    fprintf(stderr, mysql_stmt_error(stmt));
    mysql_stmt_close(stmt);
    return -1;
}


//  函数用途：username 是否已被注册；
//  used in register, login and change factor case
int validate_username(MYSQL* my_connection, const char * user_name){
    
    // input 
    size_t username_size=strlen(user_name);
    // result 
    char * ret_username=malloc(RESULT_BUFFER_MAX_SIZE);
    size_t ret_username_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT user_name FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        ret_username, &ret_username_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        free(ret_username);
        return 0; // 帐号未被注册
    }
    else if (query_res==0){
        free(ret_username);
        return 1; // 帐号已被注册
    }
    else{
        free(ret_username);
        return -1; 
    }
}

//  预记录注册信息到 session 表中，包括 session_id, user_name, email, pubkey, email_token
int pre_record_register(MYSQL* my_connection, const char * session_id, const char * user_name, const char * email, const char * pubkey, const char * email_token){
    
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t email_size=strlen(email);
    size_t pubkey_size=strlen(pubkey);
    size_t email_token_size=strlen(email_token);
    
    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (session_type, user_name, timestamp, session_id, email, public_key, email_token) VALUES('register',?,?,?,?,?,?)",TAB_SESSION);

    const char * timestamp=get_datetime_str();
    size_t timestamp_size=19;   

    int update_res=_update_database(my_connection,sql,6,
        user_name, &username_size, MYSQL_TYPE_STRING,
        timestamp, &timestamp_size,MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,

        email,&email_size,MYSQL_TYPE_STRING,
        pubkey,&pubkey_size,MYSQL_TYPE_STRING,
        email_token, &email_token_size, MYSQL_TYPE_STRING
    );
    free(sql);
    if (update_res){ 
        return -1;
    }    
    if (update_res==0){
        return 0;  
    }
}

int record_register(MYSQL* my_connection, const char * user_name, const char * email, const char * pubkey)
{
    // construct the size variable of the input
    size_t username_size=strlen(user_name);
    size_t email_size=strlen(email);
    size_t pubkey_size=strlen(pubkey);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (user_name, email, public_key) VALUES(?,?,?)",TAB_USER_DATA);

    int update_res=_update_database(my_connection,sql,3,
        user_name, &username_size, MYSQL_TYPE_STRING,
        email, &email_size, MYSQL_TYPE_STRING,
        pubkey, &pubkey_size, MYSQL_TYPE_STRING);

    free(sql);

    if (update_res){
        return -1;  
    }
    else{
        return 0;
    }
}  



int record_login(MYSQL* my_connection, const char * session_id, const char * user_name, const char * challenge)
{
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t challenge_size=strlen(challenge);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,
        "INSERT INTO %s (user_name, timestamp, session_id, session_type, challenge) VALUES(?,?,?,'login',?)",TAB_SESSION);

    const char * datetime=get_datetime_str();
    size_t datetime_size=19;   

    int update_res=_update_database(my_connection,sql,4,
        user_name, &username_size, MYSQL_TYPE_STRING,
        datetime,&datetime_size,MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        challenge, &challenge_size, MYSQL_TYPE_STRING
    );

    free(sql);
    return update_res;
}  

int record_response(MYSQL* my_connection, const char * session_id, const char * user_name, const char * response)
{
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t response_size=strlen(response);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    
    sprintf(sql, "INSERT INTO %s (user_name, timestamp, session_id, session_type, response) VALUES(?,?,?,'login',?)",TAB_SESSION);

    const char *datetime=get_datetime_str();
    size_t datetime_size=19;

    int update_res=_update_database(my_connection,sql,4,
        user_name, &username_size, MYSQL_TYPE_STRING,
        datetime, &datetime_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        response, &response_size, MYSQL_TYPE_STRING
        );

    free(sql);
    return update_res;
}  

int record_token(MYSQL* my_connection, const char * session_id, const char * user_name, const char * token, const char * procedure)
{
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t token_size=strlen(token);
     
    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (user_name, timestamp, session_id, session_type, token) VALUES(?,?,?,'%s',?)",TAB_SESSION,procedure);

    const char *datetime=get_datetime_str();
    size_t datetime_size=19;

    int update_res=_update_database(my_connection,sql,4,
        user_name, &username_size, MYSQL_TYPE_STRING,
        datetime, &datetime_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        token, &token_size, MYSQL_TYPE_STRING
        );

    free(sql);
    return update_res;
}  



//  函数用途：将 email token 与 session 表中的 email token 进行对比；
// procedure can be 'register' or 'change factor'
int validate_email_token(MYSQL * my_connection, const char *session_id, const char * user_name, const char * email_token, const char * procedure){
    
     // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);

    // output
    char * result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,
        "SELECT email_token FROM %s WHERE user_name =? and session_id = ? and session_type= '%s' ORDER BY timestamp DESC LIMIT 1;",TAB_SESSION, procedure);
    
    int query_res=_query_database(my_connection,sql,3,
        user_name, &username_size,MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        result, &result_size,MYSQL_TYPE_STRING);
    
    free(sql);

    if (query_res==1){                                              // case 1: error
        free(result);
        return 1; // 未找到目标 change_factor_token
    }
    else if (query_res==0){
            if (memcmp(email_token,result,result_size)){            // case 2: error   
                free(result);
                return 1;                                                               
            }
            else{                                                   // case 3: success
                free(result);
                return 0;
            }
    }
    else{
        return -1;
    }
    
}


// get register email
// 使用 email_pp 进行接收
int query_register_email(MYSQL * my_connection,const char *session_id, const char * user_name, const char * email_token, const char ** email_pp){

    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t user_name_size=strlen(user_name);
    size_t email_token_size=strlen(email_token);
    
    // result
    char * result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;
    char * sql=OPENSSL_zalloc(SQL_MAX_LEN);

    sprintf(sql,"SELECT email FROM %s WHERE user_name =? and session_id = ? and session_type='%s' ORDER BY timestamp DESC LIMIT 1;",TAB_SESSION,"register");
    int query_res=_query_database(my_connection,sql,3,
        user_name, &user_name_size,MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        result, &result_size,MYSQL_TYPE_STRING);
   
    if (query_res){
        free(result);
        return query_res;
    }
    else{
        * email_pp=append_character(result,result_size,'\0');
        return 0;
    }
}

// get register pubkey
// 使用 pubkey_pp 进行接收
int query_register_pubkey(MYSQL * my_connection,const char *session_id, const char * user_name, const char * email_token, const char ** pubkey_pp){

    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t user_name_size=strlen(user_name);
    size_t email_token_size=strlen(email_token);
    
    // result
    char * result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char * sql=OPENSSL_zalloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT public_key FROM %s WHERE user_name =? and session_id = ? and session_type='%s' ORDER BY timestamp DESC LIMIT 1;",TAB_SESSION,"register");

    int query_res=_query_database(my_connection,sql,3,
        user_name, &user_name_size,MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        result, &result_size,MYSQL_TYPE_STRING);
   
    if (query_res){
        free(result);
        return query_res;
    }
    else{
        * pubkey_pp=append_character(result,result_size,'\0');
        return 0;
    }
}


int record_change_factor_token(MYSQL* my_connection, const char * session_id, const char * user_name, const char * email_token )
{   
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t email_token_size=strlen(email_token);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (user_name, timestamp, session_id, session_type, email_token) VALUES(?,?,?,'change factor',?)",TAB_SESSION);

    const char * datetime=get_datetime_str();
    size_t datetime_size=19;   

    int update_res=_update_database(my_connection,sql,4,
        user_name, &username_size, MYSQL_TYPE_STRING,
        datetime,&datetime_size,MYSQL_TYPE_STRING,   
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        email_token, &email_token_size, MYSQL_TYPE_STRING);

    free(sql);

    if (update_res){
        return -1;  
    }
    else{
        return 0;
    }   
}  
// 函数用途：查询 session 表中用户的 email
int validate_change_factor_token(MYSQL * my_connection, const char *session_id, const char * user_name, const char * change_factor_token)
{   
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t change_factor_token_size=strlen(change_factor_token);
    
    // result
    char *result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT email_token FROM %s WHERE session_id = ? and user_name =? order by timestamp desc limit 1",TAB_SESSION);
    
    int query_res=_query_database(my_connection,sql,3,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name, &username_size,MYSQL_TYPE_STRING,
        result, &result_size,MYSQL_TYPE_STRING);
    
    free(sql);

    if (query_res==1){
        return -1; // 未找到目标 change_factor_token
    }
    else if (query_res==0){
        if (memcmp(change_factor_token,result,result_size)){
            return 1;  
        }
        else{
            return 0;
        }
    }
    else{
        return -1;
    }
}    

// 将 token 与 session 表中的 token 进行对比， 
int validate_token(MYSQL * my_connection, const char * session_id, const char * user_name, const char * token)
{
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t token_size=strlen(token);

    char * result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT token FROM %s WHERE user_name =? and session_id = ? and session_type in ('login','quit') order by timestamp desc limit 1",TAB_SESSION);
    int query_res=_query_database(my_connection,sql,3,
        user_name,&username_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        result,&result_size,MYSQL_TYPE_STRING);

    free(sql);

    if (query_res==1){                                          // case: error    
        return -1;                               // 无法找到 session_id user_name 对应的 token 记录
    }
    else if (query_res==0){
        if (memcmp(token,result,result_size)){                   
            return 1;
        }
        else {                                                  // case: success    
            return 0;
        }
    }
    else{                                                       // case: error    
        return -1;
    }
    
}    

// 查询 session 表中最新的 challenge
int query_challenge(MYSQL * my_connection, const char *session_id, const char * user_name, const char **challenge_pp )
{   
    // construct the size variable of the input
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);

    // result
    char * result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT challenge FROM %s WHERE  user_name =? and session_id = ? order by timestamp desc limit 1",TAB_SESSION);
    
    int query_res=_query_database(my_connection,sql,3,
        user_name, &username_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        result,&result_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        return 1; // 无法找到 session_id user_name 对应的 challenge 记录
    }
    else if (query_res==0){
        *challenge_pp=append_character(result,result_size,'\0');
        return 0;  
    }
    else{
        return -1;
    }
}    

// 函数用途：查询 user_data 表中用户的 public_key
int query_pubkey(MYSQL * my_connection, const char * user_name, EVP_PKEY ** pubkey_pp)
{   
    // construct the size variable of the input
    size_t username_size=strlen(user_name);

    char *result=OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT public_key FROM %s WHERE user_name =?",TAB_USER_DATA);
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size,MYSQL_TYPE_STRING,
        result, &result_size,MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        return 1; // 无法找到 user_name 对应的 pubkey
    }
    if (query_res==0){
        const char  * uint8_pubkey;
        size_t  uint8_pubkey_size;
        hex_to_uint8(result, result_size, &uint8_pubkey, &uint8_pubkey_size);
        
        EVP_PKEY *ret_pkey=EVP_PKEY_new_raw_public_key_ex(NULL,"ML-DSA-44",NULL, uint8_pubkey, uint8_pubkey_size);
        if (ret_pkey==NULL){
            fprintf(stderr, "fail to create EVP_PKEY * pkey from ret_pubkey\n");
            ERR_print_errors_fp(stderr);
            return -1;
        }
        else{
            * pubkey_pp=ret_pkey;
            return 0;  
        }
    }
    if (query_res==-1){ 
        return -1;
    }
}    

// 函数用途：查询 user_data 表中用户的 data(info)
int query_data(MYSQL* my_connection, const char * user_name, const char ** data_pp){
    
    // construct the size variable of the input
    size_t username_size=strlen(user_name);
    size_t data_size;

    // result 
    char * result= OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT info FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        result, &result_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1 ){
        return 1;
    }
    else if (query_res==-1){
        return -1;
    }
    else{
        * data_pp=append_character(result,result_size,'\0');
        return 0;
    }
}
 
// 函数用途：查询 user_data 表中用户的 email
int query_email(MYSQL* my_connection, const char * user_name, const char ** email_pp){
    
    // construct the size variable of the input
    size_t username_size=strlen(user_name);

    // result 
    char * result= OPENSSL_zalloc(RESULT_BUFFER_MAX_SIZE);
    size_t result_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT email FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        result, &result_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1 ){
        return 1;
    }
    else if (query_res==-1){
        return -1;}
    else{
        return 0;
    }
}
 

int update_data(MYSQL* my_connection, const char * user_name, const char * new_data)
{    
    // construct the size variable of the input
    size_t username_size= strlen(user_name);
    size_t new_data_size=strlen(new_data);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET info = ? WHERE user_name = ?",TAB_USER_DATA);;

    int update_res=_update_database(my_connection,sql,2,
        new_data, &new_data_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING);

    free(sql);
    
    return update_res;
}  

int update_pubkey(MYSQL* my_connection, const char * user_name, const char * pubkey)
{    
    // construct the size variable of the input
    size_t username_size=strlen(user_name);
    size_t pubkey_size=strlen(pubkey);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET public_key = ? WHERE user_name = ?",TAB_USER_DATA);;

    int update_res=_update_database(my_connection,sql,2,
        pubkey, &pubkey_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING);

    free(sql);
    
    return update_res;
}  


#endif