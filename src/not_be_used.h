#include <stdio.h>
#include <string.h>

// check message deliver and parse normally
int check_deliver_and_parsing(const char * process_name, void * sender_data, void * accepter_data, size_t sender_struct_size){
    size_t ptr_size=sizeof(void *);
    size_t item_size=ptr_size+sizeof(size_t);
    size_t item_num=sender_struct_size/item_size;
    for (int i; i<item_num;i++){
        const unsigned char ** sender_data_pp=(const unsigned char **)( (char *)(sender_data)+i*item_size ); 
        const unsigned char ** accepter_data_pp=(const unsigned char **)( (char *)(accepter_data)+i*item_size ); 
        size_t data_size= *(size_t *)((char *)(sender_data)+i*item_size+ptr_size) ; // 获得 struct 内存放 item 的地址
        if ( memcmp(*sender_data_pp,*accepter_data_pp,data_size)){
            fprintf(stderr, "%s: %s",process_name,"message deliver and parsing fail\n");
            return 1;
        }
    }
    fprintf(stderr, "%s: %s",process_name,"message deliver and parsing success\n");
    return 0;
}
