# include <stdio.h>
# include "./client_process_primitive.h"

int main (int argc, char *argv[]){ 

    if (argc != 4){                                                                         
        fprintf(stderr,"parameter not enough, you need to desginate hostport, chain_file and key_file\n");
        return(1);
    }

    const char * host = argv[1];
    const char * port = argv[2];
    const char * pem_folder=argv[3];
    client_process_prim(host,port,pem_folder);
    return 0;
}
