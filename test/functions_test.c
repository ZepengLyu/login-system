#include <openssl/evp.h>
#include <string.h>
#include <mysql.h>
// #include "../src/config.h"
// #include "../src/common.h"
// #include "../src/crypto.h"
// #include "../src/server/email.h"
// #include "../src/server/database.h"

// int binary_uint8_format_test(){
//     const unsigned char * text; size_t text_size;
//     const unsigned char * _text; size_t _text_size; 
//     const unsigned char * text_; size_t text_size_; 
//     text=generate_token(); text_size=TOKEN_SIZE;
//     uint8_to_binary(text, text_size, &_text, &_text_size);
//     binary_to_uint8(_text,_text_size,&text_,&text_size_);
//     return 0;
// }

// int fill_test(){
//     const unsigned char * text_pp; size_t text_len;
//     char message_type=REGISTER_TYPE;
//     const char * data1="jack"; size_t data1_size=strlen(data1);
//     const  char * data2="anna"; size_t data2_size=strlen(data2);
    
//     fill_with_va(&text_pp,&text_len,message_type,2,(const unsigned char*)data1,data1_size,(const unsigned char*)data2,data2_size);
//     return 0;
// }

// int get_test(){
//     const char * text="1\njack\nanna"; size_t text_len=strlen(text);
//     char message_type;
//     const char * data1; size_t data1_size;
//     const  char * data2; size_t data2_size;
    
//     get_with_va((const unsigned char *)text,text_len,2,
//         (const unsigned char**)&data1,&data1_size,
//         (const unsigned char**)&data2,&data2_size);
//     return 0;
// }

int uint8_to_hex(const unsigned char * text, size_t text_size, const char ** hex_text_pp, size_t * hex_text_p){
    
    size_t _hex_text_size=text_size*2;
    char * _hex_text=malloc(_hex_text_size+1); // 由于 snprintf 的特性，未结尾留出一个 '\0'
    memset(_hex_text,48,_hex_text_size); // 48 refers to '0' in ascaii
    
    size_t offset=0;
    for (int i=0;i<text_size;i++){  
        sprintf(_hex_text+offset,"%02X", text[i]);
        offset+=2;
    }
    * hex_text_pp=_hex_text;
    * hex_text_p=_hex_text_size;
    return 0;
}
int hex_to_uint8(const unsigned char * text, size_t text_size, const char ** uint8_text_pp, size_t * uint8_text_p){
    
    size_t _uint8_text_size=text_size/2;
    char * _uint8_text=malloc(_uint8_text_size);
    memset(_uint8_text,0,_uint8_text_size); 
    
    size_t offset=0;
    for (int i=0;i<_uint8_text_size;i++){  
        sscanf(text+offset, "%2hhx", _uint8_text+i);
        offset+=2;
    }

    * uint8_text_pp=_uint8_text;
    * uint8_text_p=_uint8_text_size;
    return 0;
}

int uint8_array_to_str_test(){
    size_t message_size=3;
    unsigned char * message=malloc(message_size);
    message[0]=255;
    message[1]=127;
    message[2]=32;

    char * hex_message;
    size_t hex_message_size;
    uint8_to_hex(message,3,&hex_message,&hex_message_size);


    size_t _message_size;
    unsigned char * _message;
    hex_to_uint8(hex_message,hex_message_size,&_message,&_message_size);
    return 0;
}
int main(){
 
    // send_email("lyuzepeng@gmail.com");
    // binary_uint8_format_test();
    // get_test();
    // fill_test();
    uint8_array_to_str_test();
    
    
    
    return 0;
    
}
