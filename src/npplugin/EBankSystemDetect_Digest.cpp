
#include "EBankSystemDetect.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <string>
#include <json/json.h>
#include <encode_switch.h>

using namespace std;

string WTF_CalculateDigest(string strAppPath, int ulNid = NID_md5) 
{  

	Json::Value item;
	EVP_MD_CTX *md_ctx;
	unsigned int  digest_len = 1024;
	unsigned int  read_len = 1024;
	unsigned char read_data[1024] = {0};  
	char digest_string[1024] = { 0 };
	unsigned char digest[1024] = {0};
	int i = 0;


	item["application_path"] = strAppPath;

	item["file_path"] = strAppPath;

	FILE *pFile = fopen (strAppPath.c_str(), "rb"); 

	if (pFile)
	{
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_digests();

		md_ctx = EVP_MD_CTX_create();

		EVP_MD_CTX_init(md_ctx);

		EVP_DigestInit(md_ctx, EVP_get_digestbynid(ulNid));

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
		item["digest"] = digest_string;

		item["success"] = TRUE;
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"文件不存在，请卸载后重新安装客户端");
	}

	return item.toStyledString();
}  