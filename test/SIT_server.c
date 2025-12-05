#include <openssl/evp.h>
#include <string.h>
#include <mysql.h>
#include <unistd.h>
#include "../src/config.h"
#include "../src/common.h"
#include "../src/crypto.h"
#include "../src/server/server_api.h"
#include "../src/server/server_process.h"
// #include "../src/client/client_api.h"
// #include "../src/client/client_process.h"

#include <sys/socket.h>
#include <sys/un.h>

#define SOCKET_PATH "/tmp/mysocket.sock"
int main(){

    MYSQL * my_connection=connect_database(); 
    server_process("4443","./src/server/pem/chain.pem","./src/server/pem/server_key.pem");    

    return 0;


}