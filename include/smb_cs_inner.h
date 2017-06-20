
#ifndef _SMB_CS_INNER_API_H_
#define _SMB_CS_INNER_API_H_

#include "common.h"
#include "smb_cs.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	执行SQL语句
	*/
	COMMON_API unsigned int SMB_CS_ExecSQL(IN char *pSqlData,IN unsigned int uiSqlDataLen);

	/*
	填充证书属性
	*/
	COMMON_API unsigned int SMB_UTIL_FillCertAttr(IN OUT SMB_CS_CertificateContext *pCertCtx);

	/*
	获取证书链
	*/
	COMMON_API unsigned int SMB_CS_FindCertChain(OUT SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, IN unsigned char *pbCert, IN unsigned int uiCertLen);


#ifdef __cplusplus
}
#endif

#endif /*_SMB_CS_INNER_API_H_*/