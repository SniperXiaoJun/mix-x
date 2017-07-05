
#include "EBankSystemDetect.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <stdio.h>
#include <string>
#include <json/json.h>
#include <encode_switch.h>
#include "smb_cs.h"
#include <Windows.h>
#include <wincrypt.h>

using namespace std;

#define REG_ROOT_KEY HKEY_LOCAL_MACHINE
#define REG_VALUE_Image_PATH_KEYNAME "Image Path"
#define REG_SUB_KEY_PREFIX_CSP "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"

unsigned int __stdcall WTF_ReadCSPPath(const char *pszCSPName, char * pszDllPath, unsigned int *puiDllPathLen)
{
	unsigned int ulRet = -1;
	HKEY hKey;
	DWORD dwIndex = 0, NameSize, NameCnt, NameMaxLen, Type, DataSize, MaxDateLen;
	char SubKey[BUFFER_LEN_1K] = { 0 };

	//LPCSTR SubKey[] =  REG_SUB_KEY_PREFIX;

	char * szValueName;
	LPBYTE  szValueData;

	strcat(SubKey, REG_SUB_KEY_PREFIX_CSP);
	strcat(SubKey, "\\");
	strcat(SubKey, pszCSPName);

	if (RegOpenKeyExA(REG_ROOT_KEY, SubKey, 0, KEY_READ, &hKey) !=
		ERROR_SUCCESS)
	{
		return -1;
	}

	//获取子键信息---------------------------------------------------------------
	if (RegQueryInfoKeyA(hKey, NULL, NULL, NULL, NULL, NULL, NULL, &NameCnt, &NameMaxLen, &MaxDateLen, NULL, NULL) != ERROR_SUCCESS)
	{
		RegCloseKey(hKey);
		return -1;
	}
	//枚举键值信息--------------------------------------------------------------
	for (dwIndex = 0; dwIndex<NameCnt; dwIndex++)    //枚举键
	{
		DataSize = MaxDateLen + 1;
		NameSize = NameMaxLen + 1;
		szValueName = (char *)malloc(NameSize);
		szValueData = (LPBYTE)malloc(DataSize);

		memset(szValueName, 0, NameSize);
		memset(szValueData, 0, DataSize);

		RegEnumValueA(hKey, dwIndex, szValueName, &NameSize, NULL, &Type, szValueData, &DataSize);//读取键

		if (0 == (strcmp(szValueName, REG_VALUE_Image_PATH_KEYNAME)))
		{
			if (NULL == pszDllPath)
			{
				*puiDllPathLen = DataSize;
				ulRet = 0;
			}
			else if (*puiDllPathLen < DataSize)
			{
				*puiDllPathLen = DataSize;
				ulRet = EErr_SMB_MEM_LES;
			}
			else
			{
				*puiDllPathLen = DataSize;
				memcpy(pszDllPath, szValueData, DataSize);
				ulRet = 0;
			}

			break;
		}

		free(szValueName);
		free(szValueData);
		szValueName = 0;
		szValueData = 0;
	}

	RegCloseKey(hKey);


	return ulRet;
}

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


string WTF_CheckCSPWithFileInfo()
{
	SMB_CS_FileInfo_NODE *pHeader = NULL;
	SMB_CS_FileInfo_NODE *pNode = NULL;
	EVP_MD_CTX *md_ctx;
	unsigned int  read_len = 1024;
	unsigned char read_data[1024] = { 0 };
	unsigned int  digest_len = 1024;
	unsigned char digest[1024] = { 0 };
	int i = 0;
	Json::Value values;
	Json::Value::Members members;
	Json::Value::Members::iterator it;

	SMB_CS_Init();
	SMB_CS_EnumFileInfo(&pHeader);

	pNode = pHeader;

	while (pNode)
	{
		Json::Value item;
		HCRYPTPROV	hCryptProv = NULL;

		char filePath[1024] = { 0 };
		char fileMD5Record[128] = { 0 };
		char fileMD5Calculate[128] = { 0 };
		char fileCategory[128] = { 0 };
		char fileType[128] = { 0 };
		char fileName[128] = { 0 };

		memcpy(filePath, pNode->ptr_data->stPath.data, pNode->ptr_data->stPath.length);
		memcpy(fileMD5Record, pNode->ptr_data->stDigestMD5.data, pNode->ptr_data->stDigestMD5.length);
		memcpy(fileCategory, pNode->ptr_data->stCategory.data, pNode->ptr_data->stCategory.length);
		memcpy(fileName, pNode->ptr_data->stName.data, pNode->ptr_data->stName.length);
		memcpy(fileType, pNode->ptr_data->stFileType.data, pNode->ptr_data->stFileType.length);

		item["filePath"] = filePath;
		item["fileMD5Record"] = fileMD5Record;
		item["fileName"] = fileName;
		item["fileType"] = fileType;

		for (i = 0; i < strlen(fileType); i++)
		{
			if (fileType[i] >= 'a' && fileType[i] <= 'z')
			{
				fileType[i] = fileType[i] - 32;
			}
			else
			{
				fileType[i] = fileType[i];
			}
		}

		if (0 == strcmp(fileType, "CSP"))
		{
			FILE *pFile = fopen(filePath, "rb");

			if (pFile)
			{
				OpenSSL_add_all_algorithms();
				OpenSSL_add_all_digests();

				md_ctx = EVP_MD_CTX_create();

				EVP_MD_CTX_init(md_ctx);

				EVP_DigestInit(md_ctx, EVP_get_digestbynid(NID_md5));

				while ((read_len = fread(read_data, 1, 1024, pFile)) > 0)
				{
					EVP_DigestUpdate(md_ctx, read_data, read_len);
				}

				EVP_DigestFinal(md_ctx, digest, &digest_len);

				EVP_MD_CTX_cleanup(md_ctx);

				fclose(pFile);

				for (i = 0; i < digest_len; i++)
				{
					sprintf(fileMD5Calculate + i * 2, "%02X", digest[i]); // sprintf????  
				}
				item["fileMD5Calculate"] = fileMD5Calculate;

				for (i = 0; i < strlen(fileMD5Record); i++)
				{
					if (fileMD5Record[i] >= 'a' && fileMD5Record[i] <= 'z')
					{
						fileMD5Record[i] = fileMD5Record[i] - 32;
					}
					else
					{
						fileMD5Record[i] = fileMD5Record[i];
					}
				}

				item["fileMD5Calculate"] = fileMD5Calculate;

				if (0 == strcmp(fileMD5Calculate, fileMD5Record))
				{
					item["success"] = TRUE;
				}
				else
				{
					item["success"] = FALSE;
				}
			}
			else
			{
				item["success"] = FALSE;
				item["msg"] = utf8_encode(L"文件不存在，请检测文件是否存在");
			}

			values[fileCategory]["success"] = FALSE;

			if (!CryptAcquireContextA(&hCryptProv, NULL,
				fileCategory, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{

			}
			else
			{
				values[fileCategory]["success"] = TRUE;

				CryptReleaseContext(hCryptProv, 0);
			}

			if (!CryptAcquireContextA(&hCryptProv, NULL,
				fileCategory, PROV_RSA_FULL, 0))
			{

			}
			else
			{
				values[fileCategory]["success"] = TRUE;

				CryptReleaseContext(hCryptProv, 0);
			}

			values[fileCategory]["fileList"].append(item);
		}

		pNode = pNode->ptr_next;
	}

	members = values.getMemberNames();
	for (it = members.begin(); it != members.end(); it++)
	{
		char dllPath[1024] = { 0 };
		unsigned int dllPathLen = 1024;
		bool bFlagDllExist = false;
		int j = 0;

		WTF_ReadCSPPath(it->c_str(), dllPath, &dllPathLen);

		if (0 == strlen(dllPath))
		{
			values[*it]["success"] = FALSE;
			values[*it]["msg"] = utf8_encode(L"未找见注册表路径");
			continue;
		}

		for (i = 0; i < values[*it]["fileList"].size(); i++)
		{
			if (values[*it]["fileList"][i]["success"].asBool() == false)
			{
				values[*it]["success"] = FALSE;
			}


			for (j = strlen(dllPath); j > 0; j--)
			{
				if ('\\' == dllPath[j] || '/' == dllPath[j])
				{
					break;
				}
			}

			if (NULL != strstr(values[*it]["fileList"][i]["filePath"].asCString(), &dllPath[j + 1]))
			{
				bFlagDllExist = true;
			}
		}

		if (!bFlagDllExist)
		{
			values[*it]["success"] = FALSE;
			values[*it]["msg"] = utf8_encode(L"未找见匹配注册表的数据库文件信息");
		}
	}

	return values.toStyledString();
}

string WTF_CheckCSPItemWithFileInfo(string strCspName)
{
	SMB_CS_FileInfo_NODE *pHeader = NULL;
	SMB_CS_FileInfo_NODE *pNode = NULL;
	EVP_MD_CTX *md_ctx;
	unsigned int  read_len = 1024;
	unsigned char read_data[1024] = { 0 };
	unsigned int  digest_len = 1024;
	unsigned char digest[1024] = { 0 };
	int i = 0;
	Json::Value values;
	char dllPath[1024] = { 0 };
	unsigned int dllPathLen = 1024;
	bool bFlagDllExist = false;
	int j = 0;

	SMB_CS_Init();
	SMB_CS_EnumFileInfo(&pHeader);

	pNode = pHeader;

	values["cspName"] = strCspName;

	while (pNode)
	{
		Json::Value item;
		HCRYPTPROV	hCryptProv = NULL;

		char filePath[1024] = { 0 };
		char fileMD5Record[128] = { 0 };
		char fileMD5Calculate[128] = { 0 };
		char fileCategory[128] = { 0 };
		char fileType[128] = { 0 };
		char fileName[128] = { 0 };

		memcpy(filePath, pNode->ptr_data->stPath.data, pNode->ptr_data->stPath.length);
		memcpy(fileMD5Record, pNode->ptr_data->stDigestMD5.data, pNode->ptr_data->stDigestMD5.length);
		memcpy(fileCategory, pNode->ptr_data->stCategory.data, pNode->ptr_data->stCategory.length);
		memcpy(fileName, pNode->ptr_data->stName.data, pNode->ptr_data->stName.length);
		memcpy(fileType, pNode->ptr_data->stFileType.data, pNode->ptr_data->stFileType.length);

		item["filePath"] = filePath;
		item["fileMD5Record"] = fileMD5Record;
		item["fileName"] = fileName;
		item["fileType"] = fileType;

		for (i = 0; i < strlen(fileType); i++)
		{
			if (fileType[i] >= 'a' && fileType[i] <= 'z')
			{
				fileType[i] = fileType[i] - 32;
			}
			else
			{
				fileType[i] = fileType[i];
			}
		}

		if (0 == strcmp(fileType, "CSP") && 0 == strcmp(fileCategory, strCspName.c_str()))
		{
			FILE *pFile = fopen(filePath, "rb");

			if (pFile)
			{
				OpenSSL_add_all_algorithms();
				OpenSSL_add_all_digests();

				md_ctx = EVP_MD_CTX_create();

				EVP_MD_CTX_init(md_ctx);

				EVP_DigestInit(md_ctx, EVP_get_digestbynid(NID_md5));

				while ((read_len = fread(read_data, 1, 1024, pFile)) > 0)
				{
					EVP_DigestUpdate(md_ctx, read_data, read_len);
				}

				EVP_DigestFinal(md_ctx, digest, &digest_len);

				EVP_MD_CTX_cleanup(md_ctx);

				fclose(pFile);

				for (i = 0; i < digest_len; i++)
				{
					sprintf(fileMD5Calculate + i * 2, "%02X", digest[i]); // sprintf????  
				}
				item["fileMD5Calculate"] = fileMD5Calculate;

				for (i = 0; i < strlen(fileMD5Record); i++)
				{
					if (fileMD5Record[i] >= 'a' && fileMD5Record[i] <= 'z')
					{
						fileMD5Record[i] = fileMD5Record[i] - 32;
					}
					else
					{
						fileMD5Record[i] = fileMD5Record[i];
					}
				}

				item["fileMD5Calculate"] = fileMD5Calculate;

				if (0 == strcmp(fileMD5Calculate, fileMD5Record))
				{
					item["success"] = TRUE;
				}
				else
				{
					item["success"] = FALSE;
				}
			}
			else
			{
				item["success"] = FALSE;
				item["msg"] = utf8_encode(L"文件不存在，请检测文件是否存在");
			}

			values["success"] = FALSE;

			if (!CryptAcquireContextA(&hCryptProv, NULL,
				fileCategory, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{

			}
			else
			{
				values["success"] = TRUE;

				CryptReleaseContext(hCryptProv, 0);
			}

			if (!CryptAcquireContextA(&hCryptProv, NULL,
				fileCategory, PROV_RSA_FULL, 0))
			{

			}
			else
			{
				values["success"] = TRUE;

				CryptReleaseContext(hCryptProv, 0);
			}

			values["fileList"].append(item);
		}

		pNode = pNode->ptr_next;
	}

	WTF_ReadCSPPath(strCspName.c_str(), dllPath, &dllPathLen);

	if (0 == strlen(dllPath))
	{
		values["success"] = FALSE;
		values["msg"] = utf8_encode(L"未找见注册表路径");
	}

	for (i = 0; i < values["fileList"].size(); i++)
	{
		if (values["fileList"][i]["success"].asBool() == false)
		{
			values["success"] = FALSE;
		}

		for (j = strlen(dllPath); j > 0; j--)
		{
			if ('\\' == dllPath[j] || '/' == dllPath[j])
			{
				break;
			}
		}

		if (NULL != strstr(values["fileList"][i]["filePath"].asCString(), &dllPath[j + 1]))
		{
			bFlagDllExist = true;
		}
	}

	if (!bFlagDllExist)
	{
		values["success"] = FALSE;
		values["msg"] = utf8_encode(L"未找见匹配注册表的数据库文件信息");
	}

	return values.toStyledString();
}



string WTF_CheckFileMd5()
{
	SMB_CS_FileInfo_NODE *pHeader = NULL;
	SMB_CS_FileInfo_NODE *pNode = NULL;
	EVP_MD_CTX *md_ctx;
	unsigned int  read_len = 1024;
	unsigned char read_data[1024] = { 0 };
	unsigned int  digest_len = 1024;
	unsigned char digest[1024] = { 0 };
	int i = 0;
	Json::Value values;
	Json::Value::Members members;
	Json::Value::Members::iterator it;

	SMB_CS_Init();
	SMB_CS_EnumFileInfo(&pHeader);

	pNode = pHeader;

	while (pNode)
	{
		Json::Value item;
		HCRYPTPROV	hCryptProv = NULL;

		char filePath[1024] = { 0 };
		char fileMD5Record[128] = { 0 };
		char fileMD5Calculate[128] = { 0 };
		char fileCategory[128] = { 0 };
		char fileType[128] = { 0 };
		char fileName[128] = { 0 };

		memcpy(filePath, pNode->ptr_data->stPath.data, pNode->ptr_data->stPath.length);
		memcpy(fileMD5Record, pNode->ptr_data->stDigestMD5.data, pNode->ptr_data->stDigestMD5.length);
		memcpy(fileCategory, pNode->ptr_data->stCategory.data, pNode->ptr_data->stCategory.length);
		memcpy(fileName, pNode->ptr_data->stName.data, pNode->ptr_data->stName.length);
		memcpy(fileType, pNode->ptr_data->stFileType.data, pNode->ptr_data->stFileType.length);

		item["filePath"] = filePath;
		item["fileMD5Record"] = fileMD5Record;
		item["fileName"] = fileName;
		item["fileType"] = fileType;

		for (i = 0; i < strlen(fileType); i++)
		{
			if (fileType[i] >= 'a' && fileType[i] <= 'z')
			{
				fileType[i] = fileType[i] - 32;
			}
			else
			{
				fileType[i] = fileType[i];
			}
		}

		if (0 == strcmp(fileType, "FILE"))
		{
			FILE *pFile = fopen(filePath, "rb");

			if (pFile)
			{
				OpenSSL_add_all_algorithms();
				OpenSSL_add_all_digests();

				md_ctx = EVP_MD_CTX_create();

				EVP_MD_CTX_init(md_ctx);

				EVP_DigestInit(md_ctx, EVP_get_digestbynid(NID_md5));

				while ((read_len = fread(read_data, 1, 1024, pFile)) > 0)
				{
					EVP_DigestUpdate(md_ctx, read_data, read_len);
				}

				EVP_DigestFinal(md_ctx, digest, &digest_len);

				EVP_MD_CTX_cleanup(md_ctx);

				fclose(pFile);

				for (i = 0; i < digest_len; i++)
				{
					sprintf(fileMD5Calculate + i * 2, "%02X", digest[i]); // sprintf????  
				}
				item["fileMD5Calculate"] = fileMD5Calculate;

				for (i = 0; i < strlen(fileMD5Record); i++)
				{
					if (fileMD5Record[i] >= 'a' && fileMD5Record[i] <= 'z')
					{
						fileMD5Record[i] = fileMD5Record[i] - 32;
					}
					else
					{
						fileMD5Record[i] = fileMD5Record[i];
					}
				}

				item["fileMD5Calculate"] = fileMD5Calculate;

				if (0 == strcmp(fileMD5Calculate, fileMD5Record))
				{
					item["success"] = TRUE;
				}
				else
				{
					item["success"] = FALSE;
				}
			}
			else
			{
				item["success"] = FALSE;
				item["msg"] = utf8_encode(L"文件不存在，请检测文件是否存在");
			}

			values[fileCategory]["fileList"].append(item);
		}

		pNode = pNode->ptr_next;
	}

	members = values.getMemberNames();
	for (it = members.begin(); it != members.end(); it++)
	{
		int j = 0;

		for (i = 0; i < values[*it]["fileList"].size(); i++)
		{
			if (values[*it]["fileList"][i]["success"].asBool() == false)
			{
				values[*it]["success"] = FALSE;
			}
		}
	}

	return values.toStyledString();
}

typedef ULONG(*pf_InsertKeyType) (OUT ULONG* BankID, OUT ULONG* USBKeyID);
typedef ULONG(*pf_CheckEnv) (IN ULONG BankID, IN ULONG USBKeyID);
typedef ULONG(*pf_GetTokenInfo) (IN ULONG BankID, IN ULONG USBKeyID);
typedef LPSTR(*pf_GetLastXMLCheckCode) ();

string WTF_ReadUkeyType()
{
	SMB_CS_FileInfo_NODE *pHeader = NULL;
	SMB_CS_FileInfo_NODE *pNode = NULL;
	EVP_MD_CTX *md_ctx;
	unsigned int  read_len = 1024;
	unsigned char read_data[1024] = { 0 };
	unsigned int  digest_len = 1024;
	unsigned char digest[1024] = { 0 };
	int i = 0;
	Json::Value values;


	pf_InsertKeyType fInsertKeyType = NULL;
	pf_CheckEnv fCheckEnv = NULL;
	pf_GetTokenInfo fGetTokenInfo = NULL;
	pf_GetLastXMLCheckCode fGetLastXMLCheckCode = NULL;

	SMB_CS_Init();
	SMB_CS_EnumFileInfo(&pHeader);

	pNode = pHeader;

	while (pNode)
	{
		Json::Value item;
		HCRYPTPROV	hCryptProv = NULL;

		char filePath[1024] = { 0 };
		char fileMD5Record[128] = { 0 };
		char fileMD5Calculate[128] = { 0 };
		char fileCategory[128] = { 0 };
		char fileType[128] = { 0 };
		char fileName[128] = { 0 };

		memcpy(filePath, pNode->ptr_data->stPath.data, pNode->ptr_data->stPath.length);
		memcpy(fileMD5Record, pNode->ptr_data->stDigestMD5.data, pNode->ptr_data->stDigestMD5.length);
		memcpy(fileCategory, pNode->ptr_data->stCategory.data, pNode->ptr_data->stCategory.length);
		memcpy(fileName, pNode->ptr_data->stName.data, pNode->ptr_data->stName.length);
		memcpy(fileType, pNode->ptr_data->stFileType.data, pNode->ptr_data->stFileType.length);

		item["filePath"] = filePath;
		item["fileMD5Record"] = fileMD5Record;
		item["fileName"] = fileName;
		item["fileType"] = fileType;

		for (i = 0; i < strlen(fileType); i++)
		{
			if (fileType[i] >= 'a' && fileType[i] <= 'z')
			{
				fileType[i] = fileType[i] - 32;
			}
			else
			{
				fileType[i] = fileType[i];
			}
		}

		if (0 == strcmp(fileType, "CHECK_LAISHANG"))
		{
			FILE *pFile = fopen(filePath, "rb");

			if (pFile)
			{
				OpenSSL_add_all_algorithms();
				OpenSSL_add_all_digests();

				md_ctx = EVP_MD_CTX_create();

				EVP_MD_CTX_init(md_ctx);

				EVP_DigestInit(md_ctx, EVP_get_digestbynid(NID_md5));

				while ((read_len = fread(read_data, 1, 1024, pFile)) > 0)
				{
					EVP_DigestUpdate(md_ctx, read_data, read_len);
				}

				EVP_DigestFinal(md_ctx, digest, &digest_len);

				EVP_MD_CTX_cleanup(md_ctx);

				fclose(pFile);

				for (i = 0; i < digest_len; i++)
				{
					sprintf(fileMD5Calculate + i * 2, "%02X", digest[i]); // sprintf????  
				}
				item["fileMD5Calculate"] = fileMD5Calculate;

				for (i = 0; i < strlen(fileMD5Record); i++)
				{
					if (fileMD5Record[i] >= 'a' && fileMD5Record[i] <= 'z')
					{
						fileMD5Record[i] = fileMD5Record[i] - 32;
					}
					else
					{
						fileMD5Record[i] = fileMD5Record[i];
					}
				}

				item["fileMD5Calculate"] = fileMD5Calculate;

				if (0 == strcmp(fileMD5Calculate, fileMD5Record))
				{
					HMODULE hDll = LoadLibraryA(filePath);
					if (!hDll) {
						item["msg"] = utf8_encode(L"加载FTCX_Check.dll动态库失败");
						item["success"] = FALSE;
					}
					else
					{
						fInsertKeyType = (pf_InsertKeyType)GetProcAddress(hDll, "CK_InsertKeyType");
						if (!fInsertKeyType) {
							item["msg"] = utf8_encode(L"获取函数地址失败");
							item["success"] = FALSE;
						}
						//fCheckEnv = (pf_CheckEnv)GetProcAddress(hDll, "CK_CheckEnv");
						//if (!fCheckEnv) {
						//	values["msg"] = utf8_encode(L"获取函数地址失败");
						//	values["success"] = FALSE;
						//}
						//fGetTokenInfo = (pf_GetTokenInfo)GetProcAddress(hDll, "CK_GetTokenInfo");
						//if (!fGetTokenInfo) {
						//	values["msg"] = utf8_encode(L"获取函数地址失败");
						//	values["success"] = FALSE;
						//}
						//fGetLastXMLCheckCode = (pf_GetLastXMLCheckCode)GetProcAddress(hDll, "CK_GetLastXMLCheckCode");
						//if (!fGetLastXMLCheckCode) {
						//	values["msg"] = utf8_encode(L"获取函数地址失败");
						//	values["success"] = FALSE;
						//}


						ULONG bankID = 0;
						ULONG usbkeyID = 0;
						ULONG returnCode = 0;

						returnCode = fInsertKeyType(&bankID, &usbkeyID);

						if (0 != returnCode)
						{
							item["msg"] = utf8_encode(L"函数调用失败");
							item["success"] = FALSE;
							item["returnCode"] = (int)returnCode;
						}
						else
						{
							item["msg"] = utf8_encode(L"函数调用成功");
							item["success"] = TRUE;
							item["returnCode"] = (int)returnCode;
							item["bankID"] = (int)bankID;
							item["usbkeyID"] = (int)usbkeyID;
						}

						FreeLibrary(hDll);
					}
				}
				else
				{
					item["success"] = FALSE;
				}
			}
			else
			{
				item["success"] = FALSE;
				item["msg"] = utf8_encode(L"文件不存在，请检测文件是否存在");
			}

			values[fileCategory]["fileList"].append(item);
		}

		pNode = pNode->ptr_next;
	}

	return values.toStyledString();
}