
#include <smb_cs.h>
#include <smb_dev.h>
#include "json/json.h"
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>

using namespace std;

int main(int argc, char * argv[])
{
	SMB_CS_CertificateContext_NODE *header = NULL;

	SMB_DB_Init();

	SMB_DEV_EnumCert(&header, CERT_ALG_SM2_FLAG| CERT_ALG_RSA_FLAG,
		CERT_SIGN_FLAG| CERT_EX_FLAG, // Ç©Ãû
		CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,
		CERT_FILTER_FLAG_FALSE);


	SMB_CS_FreeCtx_NODE(&header);

	return 0;
}