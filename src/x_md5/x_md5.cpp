#include <iostream>  
#include <openssl/md5.h>

using namespace std;  
  
int main()  
{  
    MD5_CTX ctx;  
    int len = 0;  
    unsigned char buffer[1024] = {0};  
    unsigned char digest[16] = {0};  

    FILE *pFile = fopen ("D:\\show.cer", "rb"); 
      
    MD5_Init (&ctx);  
  
    while ((len = fread (buffer, 1, 1024, pFile)) > 0)  
    {  
        MD5_Update (&ctx, buffer, len);  
    }  
  
    MD5_Final (digest, &ctx);  
      
    fclose(pFile);  
      
  
    int i = 0;  
    char buf[33] = {0};  
    char tmp[3] = {0};  
    for(i = 0; i < 16; i++ )  
    {  
        sprintf(tmp,"%02X", digest[i]); // sprintf????  
        strcat(buf, tmp); // strcat????????  
    }  
      
    cout << buf << endl;  // ???md5?  
  
    return 0;  
}  