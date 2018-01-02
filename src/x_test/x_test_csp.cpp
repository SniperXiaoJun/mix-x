
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <vector>

using namespace std;

#define BUFFER_LEN_1K 1024

int function2(){
	// this is rsa suit
	DWORD       cbName;
	DWORD       dwType;
	DWORD       dwIndex = 0;
	char        pszName[BUFFER_LEN_1K];

	while (CryptEnumProviders(
		dwIndex,     // in -- dwIndex  
		NULL,        // in -- pdwReserved- set to NULL  
		0,           // in -- dwFlags -- set to zero  
		&dwType,     // out -- pdwProvType  
		NULL,        // out -- pszProvName -- NULL on the first call  
		&cbName      // in, out -- pcbProvName  
	))
	{
		//--------------------------------------------------------------------  
		//  Get the provider name.  

		if (CryptEnumProvidersA(
			dwIndex++,
			NULL,
			0,
			&dwType,
			pszName,
			&cbName     // pcbProvName -- size of pszName  
		))
		{

			if (0 != strcmp("StarKey220 CSP For SDEBANK V1.0", pszName))
			{
				continue;
			}

			DWORD dwErrCode = 0;

			BYTE containerName[1024] = { 0 };
			DWORD containerNameLen = 1024;
			HCRYPTPROV	hCryptProvForContainer = NULL;

			std::vector<std::string> containerNameList;
			int containerFirst = CRYPT_FIRST;

			if (!CryptAcquireContextA(&hCryptProvForContainer, NULL,
				pszName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				dwErrCode = GetLastError();
				CryptReleaseContext(hCryptProvForContainer, 0);
			}
			else
			{
				while (CryptGetProvParam(
					hCryptProvForContainer,
					PP_ENUMCONTAINERS,
					containerName,
					&containerNameLen,
					containerFirst))
				{
					containerFirst = CRYPT_NEXT;

					containerNameList.push_back(std::string(containerName, containerName + containerNameLen));
					containerNameLen = 1024;
				}

				CryptReleaseContext(hCryptProvForContainer, 0);
			}

			if (containerNameList.size() > 0)
			{
				for (size_t i = 0; i < containerNameList.size(); i++)
				{
					HCRYPTPROV	hCryptProv = NULL;

					if (!CryptAcquireContextA(&hCryptProv, containerNameList[i].c_str(),
						pszName, PROV_RSA_FULL, 0))
					{
						dwErrCode = GetLastError();
					}
					else
					{
						HCRYPTKEY hKey = NULL;
						DWORD dwKeyType = AT_KEYEXCHANGE;

						for (; dwKeyType <= 3; dwKeyType++)
						{
							// 获取容器中的密钥
							if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
							{
								dwErrCode = GetLastError();

								if (NTE_BAD_KEY == dwErrCode)
								{
									continue;
								}
								else
								{
									continue;
								}
							}

							ULONG ulCertLen2 = 4096;
							ULONG ulCertLen = 4096;

							char * szdata2 = new char[ulCertLen2];
							memset(szdata2, 0, ulCertLen2);

							// 导出容器中的证书
							if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata2, &ulCertLen2, 0))
							{
								dwErrCode = GetLastError();

								// 销毁密钥句柄
								CryptDestroyKey(hKey);
								continue;
							}
							else
							{
								if (AT_KEYEXCHANGE == dwKeyType)
								{

								}
								else
								{

								}

								char * szdata = new char[ulCertLen];
								memset(szdata, 0, ulCertLen);
								BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
								if (!bFlag)
								{
									dwErrCode = GetLastError();

								}


								delete szdata;

								// 销毁密钥句柄
								CryptDestroyKey(hKey);

								break;
							}
						}

						// CryptReleaseContext
						if (!CryptReleaseContext(hCryptProv, 0))
						{
							;
						}
						else
						{

						}
					}
				}
			}
			else
			{
				HCRYPTPROV	hCryptProv = NULL;

				if (!CryptAcquireContextA(&hCryptProv, NULL,
					pszName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
				{
					dwErrCode = GetLastError();
				}
				else
				{
					HCRYPTKEY hKey = NULL;
					DWORD dwKeyType = AT_KEYEXCHANGE;

					for (; dwKeyType <= AT_SIGNATURE; dwKeyType++)
					{
						// 获取容器中的密钥
						if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
						{
							dwErrCode = GetLastError();

							if (NTE_BAD_KEY == dwErrCode)
							{
								continue;
							}
							else
							{
								continue;
							}
						}

						ULONG ulCertLen2 = 4096;

						char * szdata2 = new char[ulCertLen2];
						memset(szdata2, 0, ulCertLen2);

						// 导出容器中的证书
						if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata2, &ulCertLen2, 0))
						{
							dwErrCode = GetLastError();

							// 销毁密钥句柄
							CryptDestroyKey(hKey);
							continue;
						}
						else
						{
							if (AT_KEYEXCHANGE == dwKeyType)
							{

							}
							else
							{

							}

							ULONG ulCertLen = 4096;

							char * szdata = new char[ulCertLen];
							memset(szdata, 0, ulCertLen);

							BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
							if (!bFlag)
							{
								dwErrCode = GetLastError();

							}


							delete szdata;

							// 销毁密钥句柄
							CryptDestroyKey(hKey);

							break;
						}
					}

					// CryptReleaseContext
					if (!CryptReleaseContext(hCryptProv, 0))
					{
						;
					}
					else
					{

					}
				}
			}
		}
		else
		{

		}
	}
	return 0;
}

int function3() {
	// this is rsa suit
	DWORD       cbName;
	DWORD       dwType;
	DWORD       dwIndex = 0;
	char        *pszName = "StarKey220 CSP For SDEBANK V1.0";

	DWORD dwErrCode = 0;

	BYTE containerName[1024] = { 0 };
	DWORD containerNameLen = 1024;
	HCRYPTPROV	hCryptProvForContainer = NULL;

	std::vector<std::string> containerNameList;
	int containerFirst = CRYPT_FIRST;

	if (!CryptAcquireContextA(&hCryptProvForContainer, NULL,
		pszName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
dwErrCode = GetLastError();
CryptReleaseContext(hCryptProvForContainer, 0);
	}
	else
	{
		while (CryptGetProvParam(
			hCryptProvForContainer,
			PP_ENUMCONTAINERS,
			containerName,
			&containerNameLen,
			containerFirst))
		{
			containerFirst = CRYPT_NEXT;

			containerNameList.push_back(std::string(containerName, containerName + containerNameLen));
			containerNameLen = 1024;
		}

		CryptReleaseContext(hCryptProvForContainer, 0);
	}

	if (containerNameList.size() > 0)
	{
		for (size_t i = 0; i < containerNameList.size(); i++)
		{
			HCRYPTPROV	hCryptProv = NULL;

			if (!CryptAcquireContextA(&hCryptProv, containerNameList[i].c_str(),
				pszName, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			{
				dwErrCode = GetLastError();
			}
			else
			{
				HCRYPTKEY hKey = NULL;
				DWORD dwKeyType = AT_KEYEXCHANGE;

				// 获取容器中的密钥
				if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
				{
					dwErrCode = GetLastError();

					if (NTE_BAD_KEY == dwErrCode)
					{
						continue;
					}
					else
					{
						continue;
					}
				}

				ULONG ulCertLen = 4096;

				// 导出容器中的证书
				if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &ulCertLen, 0))
				{
					dwErrCode = GetLastError();

					// 销毁密钥句柄
					CryptDestroyKey(hKey);
					continue;
				}
				else
				{
					char * szdata = new char[ulCertLen];
					memset(szdata, 0, ulCertLen);
					BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
					if (!bFlag)
					{
						dwErrCode = GetLastError();

					}

					delete szdata;

					// 销毁密钥句柄
					CryptDestroyKey(hKey);

					break;
				}


				// CryptReleaseContext
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					;
				}
				else
				{

				}
			}
		}
	}

	return 0;
}

void function4()
{
	HCERTSTORE hSysStore = NULL;
	if(hSysStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,          // The store provider type
		0,                               // The encoding type is
		// not needed
		NULL,                            // Use the default HCRYPTPROV
		CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
		// registry location
		L"MY"                            // The store name as a Unicode 
		// string
		))
	{
		printf("The system store was created successfully.\n");
	}
	else
	{
		printf("An error occurred during creation "
			"of the system store!\n");
		exit(1);
	}


	PCCERT_CONTEXT context_OUT = NULL;

	do
	{
		context_OUT = CertEnumCertificatesInStore(hSysStore, context_OUT);

		if (NULL != context_OUT)
		{
			
			CRYPT_KEY_PROV_INFO *info = 0;
			DWORD ulOutLen = 0;

			CertGetCertificateContextProperty(context_OUT, CERT_KEY_PROV_INFO_PROP_ID, info, &ulOutLen);

			info = (CRYPT_KEY_PROV_INFO *)new char[ulOutLen];

			CertGetCertificateContextProperty(context_OUT, CERT_KEY_PROV_INFO_PROP_ID, info, &ulOutLen);

			wprintf(info->pwszContainerName);

			DWORD dwErrCode;

			{

				HCRYPTPROV	hCryptProv = NULL;

				if (!CryptAcquireContextW(&hCryptProv, info->pwszContainerName,
					L"StarKey220 CSP For SDEBANK V1.0" , PROV_RSA_FULL, 0))
				{
					dwErrCode = GetLastError();
				}
				else
				{
					HCRYPTKEY hKey = NULL;
					DWORD dwKeyType = AT_KEYEXCHANGE;

					// 获取容器中的密钥
					if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
					{
						dwErrCode = GetLastError();

						if (NTE_BAD_KEY == dwErrCode)
						{
							continue;
						}
						else
						{
							continue;
						}
					}

					ULONG ulCertLen = 4096;

					// 导出容器中的证书
					if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &ulCertLen, 0))
					{
						dwErrCode = GetLastError();

						// 销毁密钥句柄
						CryptDestroyKey(hKey);
						continue;
					}
					else
					{
						char * szdata = new char[ulCertLen];
						memset(szdata, 0, ulCertLen);
						BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
						if (!bFlag)
						{
							dwErrCode = GetLastError();

						}

						delete szdata;

						// 销毁密钥句柄
						CryptDestroyKey(hKey);

						break;
					}


					// CryptReleaseContext
					if (!CryptReleaseContext(hCryptProv, 0))
					{
						;
					}
					else
					{

					}
				}
			}

		}

	} while (NULL != context_OUT);
}

int main(int argc, char * argv[])
{
	HCRYPTPROV	hCryptProv = NULL;
	DWORD dwError;
	char csp_name[128] = { 0 };

	SetLastError(0);

	function4();

	function3();

	std::fstream _file;

	_file.open("csp.conf", ios::binary | ios::in);

	if (_file)
	{
		std::ios::pos_type length;
		unsigned int ulAlgType = 0;
		char * pbSqlData = NULL;
		int pos = 0;

		// get length of file:
		_file.seekg(0, ios::end);
		length = _file.tellg();
		_file.seekg(0, ios::beg);

		pbSqlData = new char[length];

		// read data as a block:
		_file.read(pbSqlData + pos, length);

		memcpy(csp_name,pbSqlData, length);

		delete[]pbSqlData;

		_file.close();
	}
	else
	{

	}

	printf("cspname=%s\n", csp_name);

	if (!CryptAcquireContextA(&hCryptProv, NULL,
		csp_name, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use CRYPT_VERIFYCONTEXT errorecode dwError=%x\n", dwError);
	}
	else
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use CRYPT_VERIFYCONTEXT successcode dwError=%x\n", dwError);

		CryptReleaseContext(hCryptProv, 0);
	}

	SetLastError(0);
	if (!CryptAcquireContextA(&hCryptProv, NULL,
		csp_name, PROV_RSA_FULL, 0))
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use 0 errorecode dwError=%x\n", dwError);
	}
	else
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use 0 successcode dwError=%x\n", dwError);
		CryptReleaseContext(hCryptProv, 0);
	}

	return getchar();
}