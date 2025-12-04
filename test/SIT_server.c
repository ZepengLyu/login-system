#include <openssl/evp.h>
#include <string.h>
#include <mysql.h>
#include <unistd.h>
#include "../src/config.h"
#include "../src/common.h"
#include "../src/crypto.h"
#include "../src/server/server_api.h"
#include "../src/server/server_process.h"
#include "../src/client/client_api.h"
#include "../src/client/client_process.h"

#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/mysocket.sock"
int main(){
    char * buf=malloc(BUFFER_MAX_SIZE);
    MYSQL * my_connection=connect_database(); 
    server_listen(NULL,my_connection);  
    // int fd=open(local_buffer_file,O_RDONLY|O_CREAT,0644);
    // if (fd<0)
    //     printf("create fd gets problem: %s\n", strerror(errno));
    
    // int local_buffer_size=read(fd, buf, BUFFER_MAX_SIZE);
    // if (local_buffer_size<0)
    //     printf("write fails : %s\n", strerror(errno));
    
    
    //     return 0;
    

}