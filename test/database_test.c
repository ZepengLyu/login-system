#include "../src/server/database.h"



int main(){
    MYSQL_RES* res_ptr;
    int res;

    MYSQL my_connection; 
    mysql_init(&my_connection);
    if (!mysql_real_connect(&my_connection, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, CLIENT_FOUND_ROWS)) {
        printf("fail to connect to database");
        return -1;
    }
    
    // query 函数测试
    char  sql[100];
    char * user_name="monl1111i";
    char * email="123";
    unsigned char * public_key="123";

    sprintf(sql, "INSERT INTO %s (username, email, public_key) VALUES ('%s', '%s', '%s');",TAB_USER_DATA,user_name,email,public_key);

    res=query(&my_connection,sql,&res_ptr);

         
   return 0;

}

