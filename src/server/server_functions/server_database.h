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

/* 该函数应该返回查询结果中最新的一条 */

int _query_database(MYSQL * my_connection, char * sql,size_t counts,...){
    // 可变参数格式: data, data_size_p, data_type, 例如 user_name, username_size, MYSQL_TYPE_STRING
    // 这里必须是 data_size_p 否则会出现 insert 数据长度的错误
    // 不包含 result data


    MYSQL_STMT *stmt;   
    stmt = mysql_stmt_init(my_connection);
    if (stmt==NULL){
        fprintf(stderr, "mysql_stmt_init fails %s\n", mysql_stmt_error(stmt));
        return -1;
    }
    if (mysql_stmt_prepare(stmt, sql, strlen(sql))){
        fprintf(stderr, "mysql_stmt_prepare fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    };
    
    MYSQL_BIND param_bind[counts-1];
    // memset(param_bind, 0, sizeof(param_bind));

    bool is_null=0;
    va_list args;
    va_start(args, counts);

    for (int i = 0; i < counts-1; i++) {
        const char * data = va_arg(args, const char *);
        size_t * data_size_p = va_arg(args, size_t*);
        enum_field_types data_type=va_arg(args,enum_field_types);
        
        param_bind[i].is_null=&is_null;
        param_bind[i].buffer_type = data_type;
        param_bind[i].buffer =  (void *)data;
        param_bind[i].length = data_size_p;
        param_bind[i].buffer_length = *data_size_p;
    }

    if (mysql_stmt_bind_param(stmt, param_bind)) {
        fprintf(stderr, "mysql_stmt_bind_param fails: %s\n",mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "mysql_stmt_execute fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }


    MYSQL_BIND result_bind[1];
    memset(result_bind, 0, sizeof(result_bind));

    const char ** result_data_pp = va_arg(args, const unsigned char **);
    size_t * result_data_size_p = va_arg(args, size_t *);
    enum_field_types result_data_type=va_arg(args,enum_field_types);

    va_end(args);

    char * _result_data=OPENSSL_zalloc(DB_BUFFER_MAX_SIZE);
    if (_result_data==NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    size_t  _result_data_size;
    
    result_bind[0].buffer_type = result_data_type;
    result_bind[0].buffer =  _result_data;
    result_bind[0].length = &_result_data_size;
    result_bind[0].buffer_length =  DB_BUFFER_MAX_SIZE;
   
    if (mysql_stmt_bind_result(stmt, result_bind)) {
        fprintf(stderr, "mysql_stmt_bind_result fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_store_result(stmt)) {
        fprintf(stderr, "mysql_stmt_store_result fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_fetch(stmt)) {
        fprintf(stderr, "mysql_stmt_fetch falls: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return 1;
    }

    * result_data_pp=_result_data;
    * result_data_size_p= _result_data_size;
    
    return 0;

}

int _update_database(MYSQL * my_connection, char *sql,size_t counts,...){
    // 可变参数格式: data, data_size_p, data_type, 例如 user_name, username_size, MYSQL_TYPE_STRING
    // 这里必须是 data_size_p 否则会出现 insert 数据长度的错误
    // 不包含 result data

    MYSQL_STMT *stmt;   
    stmt = mysql_stmt_init(my_connection);
    if (stmt==NULL){
        fprintf(stderr, "mysql_stmt_init fails %s\n");
        return -1;
    }
    if (mysql_stmt_prepare(stmt, sql, strlen(sql))){
        fprintf(stderr, "mysql_stmt_prepare fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    };

    MYSQL_BIND param_bind[counts];
    memset(param_bind, 0, sizeof(param_bind));

    va_list args;
    va_start(args, counts);

    for (int i = 0; i < counts; i++) {
        char * data = va_arg(args, char *);
        size_t * data_size_p = va_arg(args, size_t*);

        enum_field_types data_type=va_arg(args,enum_field_types);
   
        param_bind[i].buffer_type = data_type;
        param_bind[i].buffer =(void*)data;
        param_bind[i].buffer_length= *data_size_p;
        param_bind[i].length = data_size_p;
    }

    if (mysql_stmt_bind_param(stmt, param_bind)) {
        fprintf(stderr, "mysql_stmt_bind_param fails: %s\n",mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }

    if (mysql_stmt_execute(stmt)) {
        fprintf(stderr, "mysql_stmt_execute fails: %s\n", mysql_stmt_error(stmt));
        mysql_stmt_close(stmt);
        return -1;
    }
  

        return 0;

}


/* query */
// register request callback 阶段
int validate_username(MYSQL* my_connection, const char * user_name){
    
    size_t username_size=strlen(user_name);

    const char * ret_username=malloc(USERNAME_MAX_SIZE);
    size_t  ret_username_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT user_name FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        &ret_username, &ret_username_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        return 0; // 帐号未被注册
    }
     
    if (memcmp(user_name,ret_username,ret_username_size)==0){
        return 1; // 帐号已被注册
    }

    return -1;
}
 
// register token request �?�
int validate_email_token(MYSQL * my_connection, const char *session_id, const char * user_name, const char * email_token, 
    const char ** email_pp, const char ** pubkey_pp){
        
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t email_size=strlen(email_token);

    const char *ret_email_token;
    size_t ret_email_token_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT email_token FROM %s WHERE session_id = ? and user_name =? ORDER BY email_token_timestamp DESC LIMIT 1;",TAB_REGISTER_SESSION);
    int email_token_query_res=_query_database(my_connection,sql,3,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name, &username_size,MYSQL_TYPE_STRING,
        &ret_email_token, &ret_email_token_size,MYSQL_TYPE_STRING);
    
    free(sql);

    if (email_token_query_res==1){
        return 1; // 未找到目标 change_factor_token
    }
    if (email_token_query_res==0){
        if (memcmp(email_token,ret_email_token,ret_email_token_size)==0){
            // get email
            const char *ret_email;
            size_t ret_email_size;
            sprintf(sql,"SELECT email FROM %s WHERE session_id = ? and user_name =? ORDER BY email_token_timestamp DESC LIMIT 1;",TAB_REGISTER_SESSION);
            int email_query_res=_query_database(my_connection,sql,3,
                session_id, &session_id_size, MYSQL_TYPE_STRING,
                user_name, &username_size,MYSQL_TYPE_STRING,
                &ret_email, &ret_email_size,MYSQL_TYPE_STRING);
            
            // get pubkey
            const char *ret_pubkey;
            size_t ret_pubkey_size;
            sprintf(sql,"SELECT public_key FROM %s WHERE session_id = ? and user_name =? ORDER BY email_token_timestamp DESC LIMIT 1;",TAB_REGISTER_SESSION);
            int pubkey_query_res=_query_database(my_connection,sql,3,
                session_id, &session_id_size, MYSQL_TYPE_STRING,
                user_name, &username_size,MYSQL_TYPE_STRING,
                &ret_pubkey, &ret_pubkey_size,MYSQL_TYPE_STRING);
            if (email_query_res==0&&pubkey_query_res==0)   
            {   
                *email_pp=append_character(ret_email,ret_email_size,'\0');
                *pubkey_pp=append_character(ret_pubkey,ret_pubkey_size,'\0');
                return 0;  
            }
            else
                return 1;
        }
    }
    
    return -1;
}

// update request callback 和 query request callback 阶段
int validate_token(MYSQL * my_connection, const char * session_id, const char * user_name, const char * token )
{
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t token_size=strlen(token);

    const  char * ret_token;
    size_t ret_token_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT token FROM %s WHERE session_id = ? and user_name =?",TAB_SESSION);
    int query_res=_query_database(my_connection,sql,3,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name,&username_size, MYSQL_TYPE_STRING,
        &ret_token,&ret_token_size,MYSQL_TYPE_STRING);
    free(sql);

    if (query_res==1){
        return 1; // 无法找到 session_id user_name 对应的 token 记录
    }
    if (query_res==0){
    

        if (memcmp(token,ret_token,ret_token_size)==0){
            return 0;
        }
    }
    if (query_res==-1){
        return -1;
    }
}    

// response request callback 阶段
int query_challenge(MYSQL * my_connection, const char *session_id, const char * user_name, const char **challenge_pp )
{   
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);

    // 用于在 response request callback 阶段，server 提取 challenge 
    const char *ret_challenge;
    size_t ret_challenge_size;


    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT challenge FROM %s WHERE session_id = ? and user_name =?",TAB_SESSION);
    int query_res=_query_database(my_connection,sql,3,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING,
        &ret_challenge,&ret_challenge_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        return 1; // 无法找到 session_id user_name 对应的 challenge 记录
    }
    if (query_res==0){
        const char *ret_challenge_=append_character(ret_challenge,ret_challenge_size,'\0');
        *challenge_pp=ret_challenge_;
        return 0;  
    }
    return -1;
}    

// response request callback 阶段
int query_pubkey(MYSQL * my_connection, const char * user_name, EVP_PKEY ** pubkey_pp)
{
    size_t username_size=strlen(user_name);

    const char *ret_pubkey;
    size_t ret_pubkey_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT public_key FROM %s WHERE user_name =?",TAB_USER_DATA);
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size,MYSQL_TYPE_STRING,
        &ret_pubkey, &ret_pubkey_size,MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==1){
        return 1; // 无法找到 user_name 对应的 pubkey
    }
    if (query_res==0){
        const char  * uint8_pubkey;
        size_t  uint8_pubkey_size;
        hex_to_uint8(ret_pubkey, ret_pubkey_size, &uint8_pubkey, &uint8_pubkey_size);
        
        EVP_PKEY *ret_pkey=EVP_PKEY_new_raw_public_key_ex(NULL,"ML-DSA-44",NULL, uint8_pubkey, uint8_pubkey_size);
        if (ret_pkey==NULL){
            fprintf(stderr, "fail to create EVP_PKEY * pkey from ret_pubkey\n");
            ERR_print_errors_fp(stderr);
            return 1;
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

// query request callback 阶段
int query_data(MYSQL* my_connection, const char * user_name, const char ** data_pp){
    
    size_t username_size=strlen(user_name);
    size_t data_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT info FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        data_pp, &data_size, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==-1 || query_res==1 ){
        return -1;
    }
    return 0;
}
 
// change factor request callback 阶段 
int query_email(MYSQL* my_connection, const char * user_name, const char ** email_pp){
    
    size_t username_size=strlen(user_name);

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT email FROM %s WHERE user_name =?",TAB_USER_DATA);
    
    int query_res=_query_database(my_connection,sql,2,
        user_name, &username_size, MYSQL_TYPE_STRING, 
        email_pp, email_pp, MYSQL_TYPE_STRING);
    
    free(sql);
    if (query_res==-1 || query_res==1 ){
        return -1;
    }
    return 0;
}
 
// change factor token request callback 阶段 
int validate_change_factor_token(MYSQL * my_connection, const char *session_id, const char * user_name, const char * change_factor_token)
{   
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t change_factor_token_size=strlen(change_factor_token);
    
    const char *ret_change_factor_token;
    size_t ret_change_factor_token_size;

    char *sql=malloc(SQL_MAX_LEN);
    sprintf(sql,"SELECT change_factor_token FROM %s WHERE session_id = ? and user_name =?",TAB_SESSION);
    
    int query_res=_query_database(my_connection,sql,3,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name, &username_size,MYSQL_TYPE_STRING,
        &ret_change_factor_token, &ret_change_factor_token_size,MYSQL_TYPE_STRING);
    
    free(sql);

    if (query_res==1){
        return 1; // 未找到目标 change_factor_token
    }
    if (query_res==0){
        if (memcmp(change_factor_token,ret_change_factor_token,ret_change_factor_token_size)==0){
            return 0;  
        }
    }
    return -1;

}    
/* query */

/* record */ 
int record_email_token(MYSQL* my_connection, const char * session_id, const char * user_name,  const char * email, const char * pubkey, const char * email_token){

    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t email_size=strlen(email);
    size_t pubkey_size=strlen(pubkey);
    size_t email_token_size=strlen(email_token);
    
    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (session_id, user_name, email, public_key, email_token_timestamp, email_token) VALUES(?,?,?,?,?,?)",TAB_REGISTER_SESSION);

    const char * datetime=get_datetime_str();
    size_t datetime_size=19;   

    int update_res=_update_database(my_connection,sql,6,
        session_id, &session_id_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING,
        email,&email_size,MYSQL_TYPE_STRING,
        pubkey,&pubkey_size,MYSQL_TYPE_STRING,
        datetime, &datetime_size,MYSQL_TYPE_STRING,
        email_token, &email_token_size, MYSQL_TYPE_STRING
    );
    free(sql);
    if (update_res==0){
        return 0;  
    }
    if (update_res==-1){ 
        return -1;
    }    
}

int record_register(MYSQL* my_connection, const char * user_name, const char * email, const char * pubkey)
{
    size_t username_size=strlen(user_name);
    size_t email_size=strlen(email);
    size_t pubkey_size=strlen(pubkey);


    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (user_name, email, public_key) VALUES(?,?,?)",TAB_USER_DATA);

  
    int update_res=_update_database(my_connection,sql,3,
        user_name, &username_size, MYSQL_TYPE_STRING,
        email, &email_size, MYSQL_TYPE_STRING,
        pubkey, &pubkey_size, MYSQL_TYPE_BLOB);

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
    if (update_res==1){ 
        return 1;
    } 
}  



int record_login(MYSQL* my_connection, const char * session_id, const char * user_name, const char * challenge)
{
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t challenge_size=strlen(challenge);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (session_id, user_name, challenge, login_request_timestamp) VALUES(?,?,?,?)",TAB_SESSION);

    const char * datetime=get_datetime_str();
    size_t datetime_size=19;   
    int update_res=_update_database(my_connection,sql,4,
        session_id, &session_id_size, MYSQL_TYPE_BLOB,
        user_name, &username_size, MYSQL_TYPE_STRING,
        challenge, &challenge_size, MYSQL_TYPE_BLOB,
        datetime,&datetime_size,MYSQL_TYPE_STRING
    );

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  


int record_response(MYSQL* my_connection, const char * session_id, const char * user_name, const char * response)
{
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t response_size=strlen(response);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET response=?,response_timestamp=?  where session_id= ? and user_name=?",TAB_SESSION);


    const char *datetime=get_datetime_str();
    size_t datetime_size=19;
    int update_res=_update_database(my_connection,sql,4,
        response, &response_size, MYSQL_TYPE_BLOB,
        datetime, &datetime_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_BLOB,
        user_name, &username_size, MYSQL_TYPE_STRING);
    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  


int record_token(MYSQL* my_connection, const char * session_id, const char * user_name, const char * token)
{
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t token_size=strlen(token);
     
    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET token=?,token_timestamp=? where session_id= ? and user_name=?",TAB_SESSION);


    const char *datetime=get_datetime_str();
    size_t datetime_size=19;
    int update_res=_update_database(my_connection,sql,4,
        token, &token_size, MYSQL_TYPE_BLOB,
        datetime, &datetime_size, MYSQL_TYPE_STRING,
        session_id, &session_id_size, MYSQL_TYPE_BLOB,
        user_name, &username_size, MYSQL_TYPE_STRING);

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  


int update_data(MYSQL* my_connection, const char * user_name, const char * new_data)
{    
    size_t username_size= strlen(user_name);
    size_t new_data_size=strlen(new_data);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET info = ? WHERE user_name = ?",TAB_USER_DATA);;

    int update_res=_update_database(my_connection,sql,2,
        new_data, &new_data_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING);

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  

int update_pubkey(MYSQL* my_connection, const char * user_name, const char * pubkey)
{    
    size_t username_size=strlen(user_name);
    size_t pubkey_size=strlen(pubkey);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"UPDATE %s SET public_key = ? WHERE user_name = ?",TAB_USER_DATA);;


    int update_res=_update_database(my_connection,sql,2,
        pubkey, &pubkey_size, MYSQL_TYPE_STRING,
        user_name, &username_size, MYSQL_TYPE_STRING);

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  

int record_change_factor_token(MYSQL* my_connection, const unsigned char * session_id, const char * user_name, const unsigned char * token )
{
    size_t session_id_size=strlen(session_id);
    size_t username_size=strlen(user_name);
    size_t token_size=strlen(token);

    char *sql=(char *)malloc(SQL_MAX_LEN);
    sprintf(sql,"INSERT INTO %s (session_id, user_name, login_request_timestamp,change_factor_token) VALUES(?,?,?,?)",TAB_SESSION);

    const char * datetime=get_datetime_str();
    size_t datetime_size=19;   

    int update_res=_update_database(my_connection,sql,4,
        session_id, &session_id_size, MYSQL_TYPE_BLOB,
        user_name, &username_size, MYSQL_TYPE_STRING,
        datetime,&datetime_size,MYSQL_TYPE_STRING,   
        token, &token_size, MYSQL_TYPE_BLOB);

    free(sql);

    if (update_res==0){
        return 0;  
    }

    if (update_res==-1){ 
        return -1;
    }    
}  

#endif