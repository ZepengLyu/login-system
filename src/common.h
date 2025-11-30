#ifndef COMMON_H
#define COMMON_H
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "./config.h"
#include "./message_type.h"



const char * append_character(const char * token,size_t token_size, char c){
    char * token_text= (char *)malloc(token_size + 1);
    memcpy(token_text,token,token_size);
    token_text[token_size]=c;
    return token_text;
}

size_t find_delimiter(const unsigned char * buf, size_t buf_size, size_t index){
    //这里 index 是 the start point to find
    unsigned char* result = (unsigned char*)memchr(buf+index,0x0A,buf_size-index);
    return result-buf;
}


int fill_with_va(const unsigned char ** text_pp, size_t * text_len_p, char message_type, int data_count,...){
    
    if (data_count <= 0) {
        fprintf(stderr,"data count<=0");
        return -1;
    }
    // 首先获得 text 的长度
    va_list args;
    size_t text_len=1;

    va_start(args, data_count);
    for (int i = 0; i < data_count; i++) {
        const unsigned char * data = va_arg(args, const unsigned char *);
        size_t data_size = va_arg(args, size_t);
        text_len += data_size+1;
    }
    va_end(args);

    unsigned char *text = OPENSSL_zalloc(text_len);
    if (text==NULL){
        fprintf(stderr,"text allocation gets problem");
        exit(1);
    }

    // 填入数据
    text[0]=message_type;
    int offset=1;
    va_start(args, data_count);
    for (int i = 0; i < data_count; i++) {
        const unsigned char * data  = va_arg(args, const unsigned char *);
        size_t data_size = va_arg(args, size_t);
        
        text[offset]='\n';
        offset++;
        if (data && data_size > 0) {
            memcpy(text + offset, data, data_size);
            offset += data_size;
        }

    }
    va_end(args);

    *text_pp = text;
    *text_len_p = text_len;

    return 0;    
}

int get_with_va(const unsigned char * text, size_t text_size, int data_count,...){
   
    if (data_count <= 0) {
        fprintf(stderr,"data count<=0");
        return 1;
    }

    size_t delimiter_indices[data_count];
    size_t offset=0;
    for (int i=0;i<data_count;i++){
        delimiter_indices[i]=find_delimiter(text, text_size, offset); 
        offset= delimiter_indices[i]+1;
    }

    va_list args;
    va_start(args,data_count);
    
    for (int i=0;i<data_count-1;i++){
        const unsigned char ** data_pp=va_arg(args, const unsigned char **);
        size_t * data_size_p=va_arg(args, size_t *);
        size_t _data_size=delimiter_indices[i+1]-delimiter_indices[i]-1;
        unsigned char *_data = OPENSSL_zalloc(_data_size);  
        memcpy(_data, text+delimiter_indices[i]+1, _data_size);
        *data_pp=_data;
        *data_size_p=_data_size;
    }

    const unsigned char ** data_pp=va_arg(args, const unsigned char **);
    size_t * data_size_p=va_arg(args, size_t *);
    size_t _data_size=text_size-delimiter_indices[data_count-1]-1;
    unsigned char *_data = OPENSSL_zalloc(_data_size);  
    memcpy(_data, text+delimiter_indices[data_count-1]+1, _data_size);
    *data_pp=_data;
    *data_size_p=_data_size;
    return 0;


}

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

int hex_to_uint8(const char * text, size_t text_size, const unsigned char ** uint8_text_pp, size_t * uint8_text_p){
    
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



int uint8_to_binary(const unsigned char * text, size_t text_size, const char ** binarytext_pp, size_t *binarytext_size_p){
    
    size_t _binary_text_size=text_size*8;
    char * _binary_text=malloc(_binary_text_size);
    memset(_binary_text,48,_binary_text_size);
    int index=0;

    for (int i=0;i<text_size;i++){
        for (int j=7;j>=0;j--){
            _binary_text[index] = (text[i]& (1<<j))? '1':'0';
            index++;
        }
    }
    *binarytext_pp=_binary_text;
    *binarytext_size_p=_binary_text_size;
    return 0;
}  

int binary_to_uint8(char * binary_text, size_t binary_text_size, const unsigned char ** text_pp, size_t * text_size_p){
    
    size_t _text_size=binary_text_size/8;
    unsigned char * _text=malloc(_text_size);
    memset(_text,0,_text_size);


    for (int i=0;i<_text_size;i++){
       
        for (int j=0;j<=7;j++){
            _text[i]=_text[i]*2;
            int bit=binary_text[8*i+j]=='1'? 1:0;
            _text[i]= _text[i]+bit;
        }
    }
    *text_pp=_text;
    *text_size_p=_text_size;
    return 0;
}

char * get_datetime_str(){ 
    size_t timestamp = time(NULL);
    struct tm * timeinfo = localtime((const time_t *)&timestamp);
    char *datetime_str=OPENSSL_zalloc(DATETIME_SIZE);

    strftime(datetime_str, DATETIME_SIZE, "%Y-%m-%d %H:%M:%S", timeinfo);
    return datetime_str;
}


#endif