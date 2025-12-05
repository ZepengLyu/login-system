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


// int uint8_array_to_str(const unsigned char * uint8_array, size_t uint8_array_size, 
//     const char ** text_pp, size_t * text_size_p){
//     uint8_to_hex(uint8_array, uint8_array_size, text_pp, text_size_p);
//     return 0;     
// }

// int str_to_uint8_array(const char * text, size_t text_size, 
//     unsigned char ** uint8_array_pp, size_t * uint8_array_size_p)
// {
//     hex_to_uint8(text, text_size, uint8_array_pp, uint8_array_size_p);
//     return 0;
// }



// int uint8_to_binary(const unsigned char * text, size_t text_size, const char ** binarytext_pp, size_t *binarytext_size_p){
    
//     size_t _binary_text_size=text_size*8;
//     char * _binary_text=malloc(_binary_text_size);
//     memset(_binary_text,48,_binary_text_size);
//     int index=0;

//     for (int i=0;i<text_size;i++){
//         for (int j=7;j>=0;j--){
//             _binary_text[index] = (text[i]& (1<<j))? '1':'0';
//             index++;
//         }
//     }
//     *binarytext_pp=_binary_text;
//     *binarytext_size_p=_binary_text_size;
//     return 0;
// }  

// int binary_to_uint8(char * binary_text, size_t binary_text_size, const unsigned char ** text_pp, size_t * text_size_p){
    
//     size_t _text_size=binary_text_size/8;
//     unsigned char * _text=malloc(_text_size);
//     memset(_text,0,_text_size);


//     for (int i=0;i<_text_size;i++){
       
//         for (int j=0;j<=7;j++){
//             _text[i]=_text[i]*2;
//             int bit=binary_text[8*i+j]=='1'? 1:0;
//             _text[i]= _text[i]+bit;
//         }
//     }
//     *text_pp=_text;
//     *text_size_p=_text_size;
//     return 0;
// }
