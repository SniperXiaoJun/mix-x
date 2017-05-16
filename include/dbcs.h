
#ifndef _DBCS_API_H_
#define _DBCS_API_H_


#include "common.h"

typedef struct _DBCS_Data
{
	unsigned char *data;            // 数据
	unsigned int length;            // 长度
}DBCS_Data;

typedef struct _DBCS_CertificateAttr
{
	DBCS_Data stSKFName;			// SKF接口名称
	DBCS_Data stDeviceName;			// 设备名称
	DBCS_Data stApplicationName;	// 应用名称
	DBCS_Data stContainerName;		// 容器名称
	DBCS_Data stCommonName;		    // 通用名 显示设备名
	DBCS_Data stSubject;    		// 主题项
	DBCS_Data stIsuue;              // 颁发者
	DBCS_Data stPublicKey;          // 公钥
	DBCS_Data stSerialNumber;       // 序列号
	DBCS_Data stVendorData;         // 用户自定义数据
	unsigned char cAlgType;			// 证书类型
    unsigned char cUsageType;		// 签名加密
	unsigned int ulVerify;			// 验证结果 WTF_CERT_VERIFY_RESULT_FLAG
	unsigned long long ulNotBefore;	// 起始
	unsigned long long ulNotAfter;	// 截止
}DBCS_CertificateAttr;

typedef struct _DBCS_CertificateFindAttr
{
	unsigned int uiFindFlag;        // 查找标记 以下选项按位或 1 2 4 8 16 32 64 128 ... 支持4*8=32个查找项 32与组合查找
	unsigned char cAlgType;			// 证书类型
	unsigned char cUsageType;		// 签名加密
	DBCS_Data stSubject;    		// 主题项
	DBCS_Data stIsuue;              // 颁发者
	DBCS_Data stPublicKey;          // 公钥
	DBCS_Data stSerialNumber;       // 序列号
	DBCS_Data stVendorData;         // 用户自定义数据
}DBCS_CertificateFindAttr;

typedef struct _DBCS_CertificateContent
{
	unsigned char *data;            // 数据
	unsigned int length;            // 长度
}DBCS_CertificateContent;

typedef struct _DBCS_CertificateContext
{
	DBCS_CertificateAttr     stAttr;      // 证书属性
	DBCS_CertificateContent  stContent;   // 证书内容
}DBCS_CertificateContext;

#ifdef __cplusplus
extern "C" {
#endif
	/*
		创建证书上下文
	*/
	COMMON_API unsigned int DBCS_CreateCtx(DBCS_CertificateContext *pCertificateCtx,unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
		设置用户自定义数据
	*/
	COMMON_API unsigned int DBCS_SetCtxVendor(DBCS_CertificateContext *pCertificateCtx,unsigned char *pVendor, unsigned int uiVendorLen);

	/*
		释放证书上下文
	*/
	COMMON_API unsigned int DBCS_FreeCtx(DBCS_CertificateContext *pCertificateCtx,unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
		添加证书到数据库
	*/
	COMMON_API unsigned int DBCS_AddCtxToDB(DBCS_CertificateContext *pCertificateCtx);

	/*
		从数据库删除证书上
	*/
	COMMON_API unsigned int DBCS_DelCtxFromDB(DBCS_CertificateContext *pCertificateCtx);

	/*
		清空数据库
	*/
	COMMON_API unsigned int DBCS_ClrAllFromDB();

	/*
		从数据库查找证书	
	*/
	COMMON_API unsigned int DBCS_FindCtxFromDB(DBCS_CertificateFindAttr *pCertificateFindAttr,DBCS_CertificateContext *pPreCertificateCtx, DBCS_CertificateContext **pCertificateCtx);

	/*
		从数据库遍历证书
	*/
	COMMON_API unsigned int DBCS_EnumCtxFromDB(DBCS_CertificateContext *pPreCertificateCtx, DBCS_CertificateContext **pCertificateCtx);

#ifdef __cplusplus
}
#endif


#endif /*_DBCS_API_H_*/