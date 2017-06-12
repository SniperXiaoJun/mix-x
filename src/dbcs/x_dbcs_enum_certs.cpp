
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
		if (CERT_ALG_RSA_FLAG == pCertCtxNode->ptr_data->stAttr.ucCertAlgType)
		{
			SMB_UI_UIDlgViewContext(pCertCtxNode->ptr_data->stContent.data, pCertCtxNode->ptr_data->stContent.length);
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
	SMB_CS_ClrAllCtxFromDB(2);

	while (pCertCtxNode)
	{
		if (CERT_ALG_RSA_FLAG == pCertCtxNode->ptr_data->stAttr.ucCertAlgType)
		{
			SMB_UI_UIDlgViewContext(pCertCtxNode->ptr_data->stContent.data, pCertCtxNode->ptr_data->stContent.length);
		}
		else
		{
			SMB_CS_AddCtxToDB(pCertCtxNode->ptr_data, 2);
		}
		pCertCtxNode = pCertCtxNode->ptr_next;
	}

	return 0;
}

unsigned int SIGN_USE_CERT(SMB_CS_CertificateContext_NODE *pCertCtxNode)
{
	while (pCertCtxNode)
	{
		if (pCertCtxNode->ptr_data->stAttr.ucCertAlgType == CERT_ALG_SM2_FLAG && pCertCtxNode->ptr_data->stAttr.ucCertUsageType == CERT_SIGN_FLAG)
		{
			// 
			unsigned char szDigest[32] = {0};
			ECCSIGNATUREBLOB blob;
			unsigned int ulRet = 0;
			ULONG ulRetry =0;

			ulRet = SMB_DEV_SM2SignDigestByCertAttr(&pCertCtxNode->ptr_data->stAttr,"111qqq", szDigest,32, szDigest, 32, &blob, &ulRetry);

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

	SMB_DEV_EnumCert(&header, CERT_ALG_SM2_FLAG| CERT_ALG_RSA_FLAG,
		CERT_SIGN_FLAG| CERT_EX_FLAG, // Ç©Ãû
		CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,
		CERT_FILTER_FLAG_FALSE);

	SHOW_ALL_CERTS(header);

	ADD_USER_CERTS(header);

	SMB_CS_FreeCtx_NODE(&header);

	SMB_CS_EnumCtxsFromDB(&header, 2);

	//SIGN_USE_CERT(header);

	return 0;
}