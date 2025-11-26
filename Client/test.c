#include <stdio.h>


int main()
{
   FILE *fp;
   char str[60];

   if( fgets (str, 60, stdin)!=NULL ) {
      /* 向标准输出 stdout 写入内容 */
      puts(str);
   }

   
   return(0);
}