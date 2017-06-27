// portAndProcess.cpp : Defines the entry point for the console application.
//http://blog.sina.com.cn/s/blog_9fc415370101cb98.html 
//参考文献如上，但是需要根据自己的编译器进行适当变量修改；
//该测试在window7 64 旗舰P1可以运行 平台VS2015
#pragma once
//#include <iostream.h>
#include <iostream>
#include <stdio.h>
#include <afxsock.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <tchar.h>
#include <wincrypt.h>

int GetExtAuthorityIdentifier(PCCERT_CONTEXT pCertContext, unsigned char *lpscProperty, unsigned int* pulLen)
{
	int ulRes = 0;
	DWORD ulDataLen = 512;
	int ulPropertyLen = 512;
	BYTE btData[512] = { 0 };
	CHAR csProperty[512] = { 0 };
	PCERT_AUTHORITY_KEY_ID2_INFO pAuthorityKeyID2 = NULL;
	PCERT_EXTENSION pCertExt = NULL;

	if (!pCertContext)
	{
		return -1;
	}
	if (!pulLen)
	{
		return -1;
	}

	pCertExt = CertFindExtension(szOID_AUTHORITY_KEY_IDENTIFIER2, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (!pCertExt)
	{
		return -1;
	}

	pAuthorityKeyID2 = (PCERT_AUTHORITY_KEY_ID2_INFO)btData;
	if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING, szOID_AUTHORITY_KEY_IDENTIFIER2,
		pCertExt->Value.pbData, pCertExt->Value.cbData,
		CRYPT_DECODE_NOCOPY_FLAG, pAuthorityKeyID2, &ulDataLen))
	{

	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = pAuthorityKeyID2->KeyId.cbData;
	}
	else if (*pulLen < pAuthorityKeyID2->KeyId.cbData)
	{
		return -1;
	}
	else
	{
		*pulLen = pAuthorityKeyID2->KeyId.cbData;
		memcpy(lpscProperty, pAuthorityKeyID2->KeyId.pbData, *pulLen);
	}

	return 0;
}

int GetExtSubjectIdentifier(PCCERT_CONTEXT pCertContext,
	unsigned char * lpscProperty,
	unsigned int* pulLen)
{
	int ulRes = 0;
	DWORD ulDataLen = 512;
	int ulPropertyLen = 512;
	BYTE btData[512] = { 0 };
	CHAR csProperty[512] = { 0 };
	PCERT_EXTENSION pCertExt = NULL;
	PCRYPT_DATA_BLOB pDataBlob=NULL;

	if (!pCertContext)
	{
		return -1;
	}
	if (!pulLen)
	{
		return -1;
	}

	pCertExt = CertFindExtension(szOID_SUBJECT_KEY_IDENTIFIER, pCertContext->pCertInfo->cExtension, pCertContext->pCertInfo->rgExtension);
	if (!pCertExt)
	{
		return -1;
	}

	pDataBlob = (PCRYPT_DATA_BLOB)btData;
	if (CryptDecodeObject(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING | CRYPT_ASN_ENCODING, szOID_SUBJECT_KEY_IDENTIFIER,
		pCertExt->Value.pbData, pCertExt->Value.cbData,
		CRYPT_DECODE_NOCOPY_FLAG, pDataBlob, &ulDataLen))
	{

	}
	else
	{
		return GetLastError();
	}

	if (!lpscProperty)
	{
		*pulLen = pDataBlob->cbData;
	}
	else if (*pulLen < pDataBlob->cbData)
	{
		return -1;
	}
	else
	{
		*pulLen = pDataBlob->cbData;
		memcpy(lpscProperty, pDataBlob->pbData, *pulLen);
	}

	return 0;
}

int main()
{
	unsigned int ulCertLen = 0;
	unsigned char pbCert[1024] = { 0 };

	unsigned int ulDataLen = 1024;
	unsigned char pbData[1024] = { 0 };


	FILE * file = fopen("d:/show.cer", "r+b");

	if (file)
	{
		int pos = 0;
		do
		{
			pos = fread(pbCert + ulCertLen, 1, 8, file);
			ulCertLen += pos;
		} while ((pos>0));
		fclose(file);
	}

	//printf("%d", ulCertLen);

	PCCERT_CONTEXT certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, ulCertLen);

	GetExtSubjectIdentifier(certContext_IN, pbData, &ulDataLen);

	for (ULONG ulIndex = 0; ulIndex < ulDataLen; ulIndex++)
	{
		printf( "%02x ", pbData[ulIndex]);
	}
	printf("\n");
	ulDataLen = 1024;

	GetExtAuthorityIdentifier(certContext_IN, pbData, &ulDataLen);

	for (ULONG ulIndex = 0; ulIndex < ulDataLen; ulIndex++)
	{
		printf("%02x ", pbData[ulIndex]);
	}
	printf("\n");
	ulDataLen = 1024;

	return 0;
}





