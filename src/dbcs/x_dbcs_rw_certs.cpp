
#include <smb_cs.h>
#include <smb_qtui.h>
#include <smb_dev.h>
#include "json/json.h"
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>

using namespace std;

unsigned int ADD_USER_CERTS(SMB_CS_CertificateContext_NODE *pCertCtxNode)
{
	SMB_CS_ClrAllCertCtx(2);

	while (pCertCtxNode)
	{
		if (SMB_CERT_ALG_FLAG_RSA == pCertCtxNode->ptr_data->stAttr.ucCertAlgType)
		{
			
		}
		else
		{
			SMB_CS_AddCertCtx(pCertCtxNode->ptr_data, 2);
		}
		pCertCtxNode = pCertCtxNode->ptr_next;
	}

	return 0;
}

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")

int main(int argc, char * argv[])
{
	SMB_CS_CertificateContext_NODE *header = NULL;

	SMB_CS_CertificateContext *ctx = NULL;

	char smb_db_path[1024] = { 0 };

	GetEnvironmentVariableA("APPDATA", smb_db_path, MAX_PATH);

	strcat(smb_db_path, "\\suloong_sm.smb_cs.db");

	SMB_CS_SetPath(smb_db_path);

	SMB_CS_Init();

	SMB_DEV_EnumCert(&header, SMB_CERT_ALG_FLAG_SM2,
		SMB_CERT_USAGE_FLAG_SIGN | SMB_CERT_USAGE_FLAG_EX, 
		SMB_CERT_VERIFY_FLAG_NOTHING,
		SMB_CERT_FILTER_FLAG_FALSE);

	ADD_USER_CERTS(header);

	SMB_CS_FreeCertCtxLink(&header);

	return 0;
}