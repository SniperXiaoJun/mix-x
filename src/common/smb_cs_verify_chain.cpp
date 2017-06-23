#include "openssl_func_def.h"
#include "o_all_type_def.h"
#include "FILE_LOG.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "o_all_func_def.h"
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pem.h>
#include <openssl/des.h>
#include <openssl/pkcs12.h>
#include <openssl/md5.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include "sm2.h"
#include "sm3.h"
#include "string.h"
#include "openssl/x509v3.h"
#include "smb_cs.h"
#include "smb_cs_inner.h"


unsigned int OpenSSL_VerifyCertChain(
	unsigned char *pbX509Cert, unsigned int uiX509CertLen
)
{
	SMB_CS_CertificateContext_NODE *pCertCtxNodeHeader = NULL;
	
	unsigned int rv = -1;
	X509 * x509 = NULL;
	X509 * x509_CA = NULL;
	const unsigned char * ptr_in = NULL;
	X509_STORE *ca_store = NULL;
	X509_STORE_CTX *ctx = NULL;
	STACK_OF(X509) *ca_stack = NULL;
	EVP_PKEY *pk = NULL;
	int bFlag;
	unsigned char public_key[BUFFER_LEN_1K] = { 0 };
	unsigned int public_key_len = BUFFER_LEN_1K;

	ptr_in = pbX509Cert;
	x509 = d2i_X509(NULL, &ptr_in, uiX509CertLen);
	if (NULL == x509)
	{
		goto err;
	}

	pk = X509_get_pubkey(x509);
	if (!pk)
	{
		goto err;
	}

	SMB_CS_FindCertChain(&pCertCtxNodeHeader, pbX509Cert, uiX509CertLen);

	/* x509初始化 */
	ca_store = X509_STORE_new();
	ctx = X509_STORE_CTX_new();

	if (!ca_store || !ca_store)
	{
		goto err;
	}

	for (; pCertCtxNodeHeader; pCertCtxNodeHeader = pCertCtxNodeHeader->ptr_next)
	{
		ptr_in = pCertCtxNodeHeader->ptr_data->stContent.data;
		x509_CA = d2i_X509(NULL, &ptr_in, pCertCtxNodeHeader->ptr_data->stContent.length);
		if (NULL == x509_CA)
		{
			goto err;
		}

		bFlag = X509_STORE_add_cert(ca_store, x509_CA);
		if (bFlag != 1)
		{
			//goto err;
		}

		if (x509_CA)
		{
			X509_free(x509_CA);
			x509_CA = NULL;
		}
	}

	bFlag = X509_STORE_CTX_init(ctx, ca_store, x509, ca_stack);
	if (bFlag != 1)
	{
		goto err;
	}

	bFlag = X509_verify_cert(ctx);
	if (bFlag != 1)
	{
		goto err;
	}
	else
	{
		rv = 0;
	}
err:

	if (x509)
	{
		X509_free(x509);
	}
	if (x509_CA)
	{
		X509_free(x509_CA);
		x509_CA = NULL;
	}

	if (ctx)
	{
		X509_STORE_CTX_cleanup(ctx);
		X509_STORE_CTX_free(ctx);
	}

	if (ca_store)
	{
		X509_STORE_free(ca_store);
	}

	if (pCertCtxNodeHeader)
	{
		SMB_CS_FreeCertCtxLink(&pCertCtxNodeHeader);
	}

	return rv;
}

