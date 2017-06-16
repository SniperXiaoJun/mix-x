
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>


unsigned int SMB_UTIL_VerifyCert(unsigned int ulFlag, unsigned char* pbCert, unsigned int uiCertLen)
{
	unsigned int ulRet = 0;

	unsigned int ulAlgType = 0;

	
#if defined(WIN32) || defined(WINDOWS)
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = { 0 };
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;
#endif


	if (1)
	{
#if defined(WIN32) || defined(WINDOWS)
		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = -1;
			goto err;
		}
		// TIME
		if (1)
		{
			ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
			if (ulRet)
			{
				ulRet = -1;
				goto err;
			}
		}
		// SIGN CERT
		if (1)
		{
			// 打开存储区		
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
												 // not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
												 // registry location
				L"Ca"                            // The store name as a Unicode 
												 // string
			);

			if (NULL == hCertStore)
			{
				ulRet = -1;
				goto err;
			}

			// 查找颁发者证书
			certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &certContext_IN->pCertInfo->SubjectUniqueId, NULL);

			DWORD error = 0;
			if (NULL == certContext_OUT)
			{
				error = GetLastError();

				if (hCertStore)
				{
					// 关闭存储区
					CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
				}

				// 打开存储区		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
													 // not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
													 // registry location
					L"Root"                            // The store name as a Unicode 
													   // string
				);

				if (NULL == hCertStore)
				{
					ulRet = -1;
					goto err;
				}

				// 查找颁发者证书
				certContext_OUT = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_ISSUER_OF, certContext_IN, NULL);
			}

			error = GetLastError();

			if (NULL != certContext_OUT)
			{
				DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG;

				// 验证颁发者证书
				if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, uiCertLen))
				{

				}
				else
				{
					// 验证上级证书
					ulRet = SMB_UTIL_VerifyCert(ulFlag, certContext_OUT->pbCertEncoded, certContext_OUT->cbCertEncoded);
					if (ulRet)
					{
						goto err;
					}
				}

				if (!CertVerifySubjectCertificateContext(certContext_IN, certContext_OUT, &dwFlags))
				{
					ulRet = -1;
					goto err;
				}
				else
				{
					ulRet = 0;
				}

				if (dwFlags)
				{
					ulRet = -1;
				}
			}
			else
			{
				ulRet = -1;
				goto err;
			}
		}
		//CRL
		if (1)
		{

		}
#else
		ulRet = OpenSSL_VerifyCertChain(pbCert, uiCertLen);
#endif
		goto err;
	}
err:
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_OUT)
	{
		CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if (certContext_IN)
	{
		CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	return ulRet;
}

int main(int argc, char * argv[])
{
	unsigned int ulCertLen = 0;
	unsigned char pbCert[1024] = { 0 };

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

	printf("%d", ulCertLen);

	SMB_UTIL_VerifyCert( 1 , pbCert, ulCertLen);

	return 0;
}