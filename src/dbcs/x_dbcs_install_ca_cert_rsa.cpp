
#include <smb_cs.h>
#include <smb_dev.h>
#include "json/json.h"
#include <iostream>
#include <fstream>
#include <string>
#include <io.h>
#include <WinCrypt.h>

COMMON_API unsigned int CALL_CONVENTION SMB_CS_ImportCaCertRSA(unsigned char *pbCert, unsigned int uiCertLen, unsigned int *pulAlgType)
{
	unsigned int ulRet = 0;

	SMB_CS_CertificateContext * ctx = NULL;

#if defined(WIN32) || defined(WINDOWS)
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore = NULL;
#endif

	if (0 != SMB_CS_CreateCertCtx(&ctx, pbCert, uiCertLen))
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	if (SMB_CERT_ALG_FLAG_RSA == ctx->stAttr.ucCertAlgType)
	{
		if (0 == memcmp(ctx->stAttr.stIssueKeyID.data, ctx->stAttr.stSubjectKeyID.data, ctx->stAttr.stSubjectKeyID.length > ctx->stAttr.stIssueKeyID.length ? ctx->stAttr.stSubjectKeyID.length : ctx->stAttr.stIssueKeyID.length))
		{
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
		}
		else
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
		}

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMB_OPEN_STORE;
			goto err;
		}

		// 创建上下文
		certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert, uiCertLen);
		if (!certContext_IN)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		if (!CertAddCertificateContextToStore(hCertStore, certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING, NULL))
		{
			if (0x80070005 == GetLastError())
			{
				ulRet = EErr_SMB_NO_RIGHT;
			}
			else
			{
				ulRet = EErr_SMB_ADD_CERT_TO_STORE;
			}

			goto err;
		}
		else
		{
			ulRet = EErr_SMB_OK; // success
		}
	}
	else
	{
		
	}

	ulRet = EErr_SMB_OK; // success

err:
	if (ctx)
	{
		SMB_CS_FreeCertCtx(ctx);
	}
#if defined(WIN32) || defined(WINDOWS)
	if (certContext_IN)
	{
		// 释放上下文
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

using namespace std;

void filesearch(string path, int layer)
{
	struct _finddata_t filefind;

	string curr = path + "\\*.*";

	int done = 0, i, handle;

	if ((handle = _findfirst(curr.c_str(), &filefind)) == -1)return;

	while (!(done = _findnext(handle, &filefind)))
	{
		if (!strcmp(filefind.name, ".."))continue;

		for (i = 0; i<layer; i++)cout << " ";

		curr = path + "\\" + filefind.name;

		if ((_A_SUBDIR == filefind.attrib))
		{
			cout << filefind.name << "(dir)" << endl;

			filesearch(curr, layer + 1);
		}
		else
		{
			cout << filefind.name << endl;
			
			std::fstream _file;

			_file.open(curr, ios::binary | ios::in);

			if (_file)
			{
				std::ios::pos_type length;
				unsigned int ulAlgType = 0;
				unsigned char pbCaCert[1024 * 4] = { 0 };

				// get length of file:
				_file.seekg(0, ios::end);
				length = _file.tellg();
				_file.seekg(0, ios::beg);

				// read data as a block:
				_file.read((char *)pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length);
				_file.close();

				SMB_CS_ImportCaCertRSA(pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length, &ulAlgType);
			}
			else
			{

			}

		}
	}

	_findclose(handle);
}

#if defined(WIN32) || defined(WINDOWS)
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#else

#endif


int main(int argc, char * argv[])
{
	SMB_CS_CertificateContext_NODE *header = NULL;
	
	SMB_CS_EnumCertCtx(&header, 0);

	SMB_CS_DelCertCtxLink(header);

	std::string path = ".";

	filesearch(path, 1);

	return 0;
}