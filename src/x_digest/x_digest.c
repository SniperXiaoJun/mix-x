
#include <openssl/digest.h>
#include <openssl/objects.h>
#include <stdio.h>
  
int main()  
{  
	EVP_MD_CTX *md_ctx;
	unsigned int  digest_len = 1024;
	unsigned int  read_len = 1024;
    unsigned char read_data[1024] = {0};  
	char digest_string[1024] = { 0 };
    unsigned char digest[1024] = {0};
	int i = 0;

    FILE *pFile = fopen ("D:\\show.cer", "rb"); 

	md_ctx = EVP_MD_CTX_create();

	EVP_MD_CTX_init(md_ctx);

	EVP_DigestInit(md_ctx, EVP_get_digestbynid(NID_md5));

    while ((read_len = fread (read_data, 1, 1024, pFile)) > 0)
    {  
		EVP_DigestUpdate(md_ctx, read_data, read_len);
    }  
  
	EVP_DigestFinal(md_ctx, digest,&digest_len);
      
	EVP_MD_CTX_cleanup(md_ctx);

    fclose(pFile);  

    for(i = 0; i < digest_len; i++ )
    {  
        sprintf(digest_string+i*2,"%02X", digest[i]); // sprintf????  
    }  
      
	printf("digest_string = %s", digest_string);
  
    return getchar();  
}  