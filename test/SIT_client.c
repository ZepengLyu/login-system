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


int main(){
    // const char *session_id=generate_session_id(); 
    // client_register(NULL,session_id);
    client_process("localhost","4443","./src/client/pem/");
    return 0;
}
