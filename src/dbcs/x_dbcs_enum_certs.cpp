
#include <smb_cs.h>
#include <smb_qtui.h>
#include <smb_dev.h>
#include "json/json.h"
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>

using namespace std;

unsigned int SHOW_ALL_CERTS(SMB_CS_CertificateContext_NODE *pCertCtxNode)
{
	while (pCertCtxNode)
	{
		if (SMB_CERT_ALG_FLAG_RSA == pCertCtxNode->ptr_data->stAttr.ucCertAlgType)
		{
			SMB_UI_ShowUI(pCertCtxNode->ptr_data->stContent.data, pCertCtxNode->ptr_data->stContent.length);
		}
		else
		{
			SMB_QTUI_ShowUI(pCertCtxNode->ptr_data->stContent.data, pCertCtxNode->ptr_data->stContent.length);
		}
		pCertCtxNode = pCertCtxNode->ptr_next;
	}

	return 0;
}

unsigned int ADD_USER_CERTS(SMB_CS_CertificateContext_NODE *pCertCtxNode)
{
	SMB_CS_ClrAllCtx(2);

	while (pCertCtxNode)
	{
		if (SMB_CERT_ALG_FLAG_RSA == pCertCtxNode->ptr_data->stAttr.ucCertAlgType)
		{
			
		}
		else
		{
			SMB_CS_AddCtx(pCertCtxNode->ptr_data, 2);
		}
		pCertCtxNode = pCertCtxNode->ptr_next;
	}

	return 0;
}

unsigned int SIGN_USE_CERT(SMB_CS_CertificateContext_NODE *pCertCtxNode)
{
	while (pCertCtxNode)
	{
		if (pCertCtxNode->ptr_data->stAttr.ucCertAlgType == SMB_CERT_ALG_FLAG_SM2 && pCertCtxNode->ptr_data->stAttr.ucCertUsageType == SMB_CERT_USAGE_FLAG_SIGN)
		{
			// 
			unsigned char szDigest[32] = {0};
			ECCSIGNATUREBLOB blob;
			unsigned int ulRet = 0;
			ULONG ulRetry =0;

			ulRet = SMB_DEV_SM2SignByCertAttr(&pCertCtxNode->ptr_data->stAttr,"111qqq", szDigest,32, szDigest, 32, &blob, &ulRetry);

			printf("ulRet = %d, ulRetry = %d\n", ulRet, ulRetry);
		}
		pCertCtxNode = pCertCtxNode->ptr_next;
	}

	return 0;
}

int main(int argc, char * argv[])
{
	SMB_CS_CertificateContext_NODE *header = NULL;

	SMB_DB_Path_Init("smb_cs.db");
	SMB_DB_Init();

	SMB_DEV_EnumCert(&header, SMB_CERT_ALG_FLAG_SM2| SMB_CERT_ALG_FLAG_RSA,
		SMB_CERT_USAGE_FLAG_SIGN| SMB_CERT_USAGE_FLAG_EX, // Ç©Ãû
		SMB_CERT_VERIFY_FLAG_TIME | SMB_CERT_VERIFY_FLAG_CHAIN | SMB_CERT_VERIFY_FLAG_CRL,
		SMB_CERT_FILTER_FLAG_FALSE);

	SHOW_ALL_CERTS(header);

	ADD_USER_CERTS(header);

	SMB_CS_FreeCtxLink(&header);

	SMB_CS_EnumCtx(&header, 2);

	//SIGN_USE_CERT(header);

	return 0;
}