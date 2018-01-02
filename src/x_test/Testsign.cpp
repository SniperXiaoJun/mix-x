//--------------------------------------------------------------------
//  Example code 


#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

#include <atlstr.h>

#undef UNICODE
#undef _UNICODE

#pragma   comment(lib,   "Crypt32.lib")

void HandleError(char *s);

LPCTSTR pszProvider = "SafeSign CSP Version 1.0";
DWORD dwProvType = PROV_RSA_FULL;

int num = 0; 

void HexToAsic(BYTE *pb, int pblen, char *str)
{
	BYTE b1;

	for(int i = 0; i < pblen; i ++)
	{
		b1 = *(pb+i) & 0xF0;
		b1 = b1 >> 4;
		if(b1 >= 0 && b1 <=9)
			*(str+2*i) = b1 + '0';
		else
			*(str+2*i) = b1 + 'A' - 10;

		b1 = *(pb+i) & 0x0F;
		if(b1 >= 0 && b1 <=9)
			*(str+2*i+1) = b1 + '0';
		else
			*(str+2*i+1) = b1 + 'A' - 10;

	}
	str[pblen*2] = 0;

}

int signmsg(HCRYPTPROV hCryptProv1, CERT_PUBLIC_KEY_INFO* pPubkeyInfo)
{
	HCRYPTHASH hHash;

	HCRYPTKEY hKey;


	////////////////////////

	BOOL bb = CryptGetUserKey(hCryptProv1, AT_KEYEXCHANGE, &hKey);
	BYTE pPub[5000];
	DWORD dwlen = 5000;

	bb = CryptExportKey(hKey, NULL, PUBLICKEYBLOB, 0, pPub, &dwlen);
	if(!bb)
	{
		printf("export public key error");
	}

	DWORD dwCertLength;
	bb =CryptGetKeyParam (hKey, KP_CERTIFICATE, NULL, &dwCertLength, 0);
	BYTE* bCert;
	bCert = new BYTE[dwCertLength];
	bb =CryptGetKeyParam (hKey, KP_CERTIFICATE, bCert, &dwCertLength, 0);
	int t = GetLastError();

	printf("public key exported \n");




		//Create Hash object(SHA1)
		if(CryptCreateHash(
		   hCryptProv1, 
		   CALG_SHA1, 
		   0, 
		   0, 
		   &hHash)) 
		{
			 printf("The hash object has been recreated. hash=0x%x \n", hHash);
		}
		else
		{
			printf("Error during CryptCreateHash. 0x%x", GetLastError());
			return -1;
		}

		

		BYTE hash[36];
		memset(hash, 0, 36);
		if(CryptSetHashParam(hHash, HP_HASHVAL, hash, 0 ))
		{
			printf("The hash value setted. \n");
		}
		else
		{
			printf("Error during CryptSetHashParam\n");
			return -2;
		}
		
		DWORD dwSigLen= 128;
		//sign hash
		
		if(CryptSignHash(
		   hHash, 
		   AT_SIGNATURE, //AT_KEYEXCHANGE, 
		   NULL, 
		   0, 
		   NULL,	
		   &dwSigLen)) 
		{
			 printf("Signature length 0x%x found.\n",dwSigLen);
		}
		else
		{
			 printf("Error during CryptSignHash. 0x%x \n", GetLastError());
			 CryptDestroyHash(hHash);
			 CryptReleaseContext(hCryptProv1, 0);
			 return -3;
		}

		BYTE out[500];

		if(CryptSignHash(
		   hHash, 
		   AT_SIGNATURE, //AT_KEYEXCHANGE
		   NULL, 
		   0, 
		   out, 
		   &dwSigLen)) 
		{
			char str[1000];
			 printf("Signature result :\n");
			 HexToAsic(out, dwSigLen, str);
			 printf(str);
			 printf("\n");
		}
		else
		{
			 printf("Error during CryptSignHash. 0x%x \n", GetLastError());
			 return -4;
		}

		CryptDestroyHash(hHash);
		printf("DestroyHash hash = 0x%x", hHash);
		printf("____________________________\n\n");

		return 0;
}

static DWORD WINAPI ThreadProc(LPVOID lpPara)
{	
	int i = 0, rc;
	for(i = 0; i < 50; i++)
	{
		rc = signmsg((HCRYPTPROV)(*(DWORD*)lpPara), NULL);
		if(rc != 0)
		{
			printf("OOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO");
		}
	}
	return 2;
}


/*
typedef struct _VTableProvStruc {
	DWORD   Version;
	FARPROC FuncVerifyImage;
	FARPROC FuncReturnhWnd;
	DWORD   dwProvType;
	BYTE        *pbContextInfo;
	DWORD       cbContextInfo;
	LPSTR   pszProvName;
} VTableProvStruc, *PVTableProvStruc;
*/

void main(void)
{

	for(int x = 0; x < 1; x++)
	{
	
		HCRYPTPROV hCryptProv1; 
		//HCRYPTKEY phUserKey1; 

		//Open "MY" Store
		HCERTSTORE hSysStore;
/*		hSysStore = CertOpenStore(
		   CERT_STORE_PROV_SYSTEM,   // The store provider type.
		   0,                        // The encoding type is not needed.
		   NULL,                     // Use the default HCRYPTPROV.
		   CERT_SYSTEM_STORE_CURRENT_USER,
		   L"MY"                     // The store name as a Unicode string.
 		   );
*/
		hSysStore = CertOpenSystemStore(NULL, "MY");

		PCCERT_CONTEXT  pCertContext=NULL; 
		char str[1000];
		PCCERT_CONTEXT pCert[10];
		pCert[0] = NULL;

		printf("Certificates in system store:\n\n");
		//Enum the certificate in the store
		int i;
		for(i = 0; i < 10; i++)
		{
			pCertContext= CertEnumCertificatesInStore(
				hSysStore,
				pCertContext);

			if(pCertContext == NULL)
			{
				break;
			}
			
			pCert[i] = CertDuplicateCertificateContext(pCertContext);

			CertNameToStr(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
				&(pCertContext->pCertInfo->Subject),
				CERT_OID_NAME_STR,
				str,
				1000);

			SYSTEMTIME sysTime;
			char t1[100], t2[100];
			FileTimeToSystemTime(&(pCertContext->pCertInfo->NotBefore), &sysTime);
			sprintf(t1, "0x%x-0x%x-0x%x", sysTime.wYear, sysTime.wMonth, sysTime.wDay);
			FileTimeToSystemTime(&(pCertContext->pCertInfo->NotAfter), &sysTime);
			sprintf(t2, "0x%x-0x%x-0x%x", sysTime.wYear, sysTime.wMonth, sysTime.wDay);
			
			printf("Certificate(%s to %s) 0x%x :%s\n\n", t1, t2, i, str);

		}

		//don't find any certificate, exit
		if(i == 0)
		{
			printf("Have no certificate in system store!\n");
			CertCloseStore(hSysStore, 0);
			return;
		}

		//Close store
		CertCloseStore(hSysStore, 0);

		//select the certificate to do signature
		printf("Please select certificate(0, 1, 2...), e for exit: ");
		char m;
		m = getchar();
		getchar();

		if(m == 'e')
			return;
		
		int n = m - 0x30;

		if(n < 0 || n > i + 1)
		{
			printf("Input wrong!\n");
			CertCloseStore(hSysStore, 0);
			return;
		}

		BOOL bb;

		CRYPT_KEY_PROV_INFO *pvKeyProv;

		DWORD dwBufferSize1 = 0;
		//Get certificate's proprety CSP name and container name
		bb = CertGetCertificateContextProperty(pCert[n],
			CERT_KEY_PROV_INFO_PROP_ID,
			NULL,
			&dwBufferSize1);

		pvKeyProv =(CRYPT_KEY_PROV_INFO*) new BYTE[dwBufferSize1];

		bb = CertGetCertificateContextProperty(pCert[n],
			CERT_KEY_PROV_INFO_PROP_ID,
			pvKeyProv,
			&dwBufferSize1);

		
		wprintf(pvKeyProv->pwszContainerName);
		printf("\n");
		wprintf(pvKeyProv->pwszProvName);
		printf("\n");

		//Open the container
		bb = CryptAcquireContextW(&hCryptProv1,
			pvKeyProv->pwszContainerName,
			pvKeyProv->pwszProvName,
			PROV_RSA_FULL,
			0);

		delete pvKeyProv;


		if(bb)
			printf("Open Certificate successful\n");
		else
		{
			printf("open container error %X", GetLastError());
			getchar();
			return;
		}
		
		HCRYPTKEY hKey, hkey2;
		//bb = CryptGetUserKey(hCryptProv1,  AT_KEYEXCHANGE, &hKey);
		//bb = CryptGetUserKey(hCryptProv1,  AT_SIGNATURE, &hkey2);
		
		for(int i = 0; i < 1; i++)
		{
			printf("Begin %d/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n", i);
			int rc = signmsg(hCryptProv1, &(pCert[n]->pCertInfo->SubjectPublicKeyInfo));
			if(rc != 0)

			{
				printf("Signature Error!!!!!!!!!!!!!!!!!!!!\n");
				getchar();
				getchar();
				//return;
			}
			printf("End %d/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////\n", i);
		}
		printf("test finish!!!!!!!!!!!");
		getchar();
		getchar();
		return;

		DWORD dwLen = 20;
		BYTE data[1024];
		memset(data, 0x31, 20);
		//bb = CryptEncrypt(hKey, 0, TRUE, NULL, data, &dwLen, 1024);
		//bb = CryptDecrypt(hKey, 0, TRUE, NULL, data, &dwLen);

/*		
		DWORD nParam = hCryptProv1 , dwThreadID;
		Sleep(5000);
		num++;
		Sleep(5000);
		CreateThread(NULL, 0, ThreadProc, &nParam, 0, &dwThreadID);
		Sleep(5000);
		num++;
		Sleep(5000);
		CreateThread(NULL, 0, ThreadProc, &nParam, 0, &dwThreadID);
		Sleep(5000);
		num++;
		Sleep(5000);
		CreateThread(NULL, 0, ThreadProc, &nParam, 0, &dwThreadID);
		Sleep(5000);
		num++;
		Sleep(5000);
		CreateThread(NULL, 0, ThreadProc, &nParam, 0, &dwThreadID);
		Sleep(5000);
		num++;
		Sleep(5000);
		CreateThread(NULL, 0, ThreadProc, &nParam, 0, &dwThreadID);
*/
		//signmsg(hCryptProv1);
		getchar();
		CryptReleaseContext(hCryptProv1, 0);
	}
	getchar();
}
