
#include <smb_cs.h>
#include <smb_qtui.h>
#include <smb_dev.h>
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <string>
#include <io.h>
#include <list>
#include <windows.h>
using namespace std;
#include "Wincrypt.h"

extern "C" unsigned int OPF_Str2Bin(const char *pbIN, unsigned int uiINLen, unsigned char *pbOUT, unsigned int * puiOUTLen);

// 证书使用者密钥标示
string WTF_CheckCertChain(list<string> strListRootCertKeyIDHex, unsigned int uiFlag, unsigned int ulAlgType)
{
	unsigned int ulRet = 0;
	unsigned int ulOutLen = 0;
#if defined(WIN32) || defined(WINDOWS)
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_CA = NULL;
#endif
	list<string>::iterator i;
	unsigned char data_value_keyid[BUFFER_LEN_1K] = { 0 };
	unsigned int data_len_keyid = BUFFER_LEN_1K;

	CERT_ID id;

	SMB_CS_CertificateContext_NODE * ctxHeader = NULL;

	switch (ulAlgType)
	{
	case SMB_CERT_ALG_FLAG_RSA:
#if defined(WIN32) || defined(WINDOWS)
	{
		for (i = strListRootCertKeyIDHex.begin(); i != strListRootCertKeyIDHex.end(); ++i)
		{
			std::string strRootCertKeyIDHex = i->c_str();

			id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
			OPF_Str2Bin(strRootCertKeyIDHex.c_str(), strRootCertKeyIDHex.size(), data_value_keyid, &data_len_keyid);
			id.KeyId.pbData = data_value_keyid;
			id.KeyId.cbData = data_len_keyid;

			// Other common system stores include "Root", "Trust", and "Ca".
			// 打开存储�?		
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
				ulRet = EErr_SMB_OPEN_STORE;
				goto err;
			}

			certContext_CA = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_CERT_ID, &id, NULL);

			if (uiFlag)
			{
				// 验证	CA
				ulRet = SMB_CS_VerifyCert(uiFlag, certContext_CA->pbCertEncoded, certContext_CA->cbCertEncoded);
			}

			if (ulRet)
			{
				ulRet = EErr_SMB_NO_CERT_CHAIN;
				goto err;
			}
		}
	}
	break;
#endif
	case SMB_CERT_ALG_FLAG_SM2:
	{
		for (i = strListRootCertKeyIDHex.begin(); i != strListRootCertKeyIDHex.end(); ++i)
		{
			std::string strRootCertKeyIDHex = i->c_str();

			// 查找颁发者证书
			SMB_CS_CertificateFindAttr findAttr = { 0 };

			findAttr.uiFindFlag = 128;

			findAttr.stSubjectKeyID.data = (unsigned char*)strRootCertKeyIDHex.c_str();
			findAttr.stSubjectKeyID.length = strRootCertKeyIDHex.size();

			SMB_CS_FindCertCtx(&findAttr, &ctxHeader);

			if (NULL == ctxHeader)
			{
				ulRet = EErr_SMB_NO_CERT_CHAIN;
				goto err;
			}

			if (uiFlag)
			{
				// 验证	CA
				ulRet = SMB_CS_VerifyCert(uiFlag, ctxHeader->ptr_data->stContent.data, ctxHeader->ptr_data->stContent.length);
			}

			if (ulRet)
			{
				ulRet = EErr_SMB_NO_CERT_CHAIN;
				goto err;
			}
		}
	}
	break;
	default:
		break;
	}

err:
#if defined(WIN32) || defined(WINDOWS)
	// 释放上下文
	if (certContext_CA)
	{
		CertFreeCertificateContext(certContext_CA);
	}

	if (hCertStore)
	{
		// 关闭存储区
		CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}
#endif

	if (NULL != ctxHeader)
	{
		SMB_CS_FreeCertCtxLink(&ctxHeader);
	}

	return "";
}

int main(int argc, char * argv[])
{
	list<std::string> strList;

	strList.push_back("0159abe7dd3a0b59a66463d6cf200757d591e76a");

	WTF_CheckCertChain(strList, SMB_CERT_VERIFY_FLAG_TIME| SMB_CERT_VERIFY_FLAG_CHAIN| SMB_CERT_VERIFY_FLAG_CRL, SMB_CERT_ALG_FLAG_RSA);

	return 0;
}