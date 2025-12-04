# include <stdio.h>
// # include "../src/server/server_functions.h"
// # include "../src/server/server_api.h"
# include "./server_process_primitive.h"

// main 函数参数除了默认的第一个参数文件名，应该还要包括 hostport, chain_file 和 key_file 

int main (int argc, char *argv[]){ 
    if (argc != 4){                                                                         
        fprintf(stderr,"parameter not enough, you need to desginate hostport, chain_file and key_file\n");
        exit(1);
    }

    const char * hostport = argv[1];
    const char * chain_file=argv[2];
    const char * key_file=argv[3];
    // server_process_prim(hostport,chain_file,key_file);
    server_process(hostport,chain_file,key_file);
    return 0;
}

