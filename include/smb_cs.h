
#ifndef _SMB_CS_API_H_
#define _SMB_CS_API_H_


#include "common.h"

typedef struct _SMB_CS_Data
{
	unsigned char *data;            // 数据
	unsigned int length;            // 长度
}SMB_CS_Data;

typedef struct _SMB_CS_CertificateAttr
{
	SMB_CS_Data stSKFName;			// SKF接口名称
	SMB_CS_Data stDeviceName;			// 设备名称
	SMB_CS_Data stApplicationName;	// 应用名称
	SMB_CS_Data stContainerName;		// 容器名称
	SMB_CS_Data stCommonName;		    // 通用名 显示设备名
	SMB_CS_Data stSubject;    		// 主题项
	SMB_CS_Data stIsuue;              // 颁发者
	SMB_CS_Data stPublicKey;          // 公钥
	SMB_CS_Data stSerialNumber;       // 序列号
	SMB_CS_Data stVendorData;         // 用户自定义数据
	unsigned char ucCertAlgType;	// 证书类型
	unsigned char ucCertUsageType;	// 签名加密 1 签名 2 加密 3 签名加密
	unsigned int ulVerify;			// 验证结果 WTF_CERT_VERIFY_RESULT_FLAG
	unsigned long long ulNotBefore;	// 起始
	unsigned long long ulNotAfter;	// 截止
}SMB_CS_CertificateAttr;

typedef struct _SMB_CS_CertificateFindAttr
{
	unsigned int uiFindFlag;        // 查找标记 以下选项按位或 1 2 4 8 16 32 64 128 ... 支持4*8=32个查找项 32与组合查找
	unsigned char ucCertAlgType;	// 证书类型
	unsigned char ucCertUsageType;	// 签名加密
	SMB_CS_Data stSubject;    		// 主题项
	SMB_CS_Data stIsuue;              // 颁发者
	SMB_CS_Data stPublicKey;          // 公钥
	SMB_CS_Data stSerialNumber;       // 序列号
	SMB_CS_Data stVendorData;         // 用户自定义数据
}SMB_CS_CertificateFindAttr;

typedef struct _SMB_CS_CertificateContent
{
	unsigned char *data;            // 数据
	unsigned int length;            // 长度
}SMB_CS_CertificateContent;

typedef struct _SMB_CS_CertificateContext
{
	SMB_CS_CertificateAttr     stAttr;      // 证书属性
	SMB_CS_CertificateContent  stContent;   // 证书内容
}SMB_CS_CertificateContext;

typedef struct _SMB_CS_CertificateContext_NODE
{
	SMB_CS_CertificateContext *ptr_data;
	struct _SMB_CS_CertificateContext_NODE *ptr_next;
}SMB_CS_CertificateContext_NODE;

typedef enum _EErr_SMB
{
	EErr_SMB_OK,									// 成功
													// SKFERROR 0x0A000001-0x0A000032				// SKF错误码范围
													// HRESULT  0x00000000-0x00015301				// 微软错误码范围
													// HRESULT  0x8000FFFF-0x802A010A				// 微软错误码范围
													// HRESULT  .....								// 微软错误码范围

													EErr_SMB_BASE = 0xF000FFFF,						// 起始错误码
													EErr_SMB_DLL_REG_PATH,							// 注册路径
													EErr_SMB_DLL_PATH,								// 获取函数地址失败
													EErr_SMB_NO_APP,								// 没有应用
													EErr_SMB_CREATE_STORE,							// 创建存储区失败
													EErr_SMB_OPEN_STORE,							// 打开存储区失败
													EErr_SMB_NO_CERT_CHAIN,							// 没有证书链
													EErr_SMB_EXPORT_PUK,							// 导出公钥失败
													EErr_SMB_VERIFY_CERT,							// 验证证书签名失败
													EErr_SMB_VERIFY_TIME,							// 验证证书有效期失败
													EErr_SMB_CREATE_CERT_CONTEXT,					// 创建证书上下文
													EErr_SMB_ADD_CERT_TO_STORE,						// 保存证书
													EErr_SMB_NO_RIGHT,								// 没有权限
													EErr_SMB_SET_CERT_CONTEXT_PROPERTY,				// 设置属性
													EErr_SMB_INVALIDARG,                            // 参数错误
													EErr_SMB_MEM_LES,                               // 内存不足
													EErr_SMB_INVALID_ARG,                           // 参数错误
													EErr_SMB_FAIL = -1,

}EErr_SMB;

#ifdef __cplusplus
extern "C" {
#endif
	/*
	创建证书上下文
	*/
	COMMON_API unsigned int SMB_CS_CreateCtx(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
	设置用户自定义数据
	*/
	COMMON_API unsigned int SMB_CS_SetCtxVendor(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pVendor, unsigned int uiVendorLen);

	/*
	释放证书上下文
	*/
	COMMON_API unsigned int SMB_CS_FreeCtx(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
	添加证书到数据库
	*/
	COMMON_API unsigned int SMB_CS_AddCtxToDB(SMB_CS_CertificateContext *pCertificateCtx);

	/*
	从数据库删除证书上
	*/
	COMMON_API unsigned int SMB_CS_DelCtxFromDB(SMB_CS_CertificateContext *pCertificateCtx);

	/*
	清空数据库
	*/
	COMMON_API unsigned int SMB_CS_ClrAllFromDB();

	/*
	从数据库查找证书
	*/
	COMMON_API unsigned int SMB_CS_FindCtxFromDB(SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext *pPreCertificateCtx, SMB_CS_CertificateContext **pCertificateCtx);

	/*
	从数据库遍历证书
	*/
	COMMON_API unsigned int SMB_CS_EnumCtxFromDB(SMB_CS_CertificateContext *pPreCertificateCtx, SMB_CS_CertificateContext **pCertificateCtx);

	/*
	从数据库遍历SKF名称
	*/
	COMMON_API unsigned int SMB_CS_EnumSKF(char * pszSKFNames, unsigned int * puiSKFNamesLen);

	/*
	从数据库读取SKF路径
	*/
	COMMON_API unsigned int SMB_CS_ReadSKFPath(const char * pszSKFName, char * pszDllPath, unsigned int *puiDllPathLen);
	
	/*
	从数据库读取SKF签名类型
	*/
	COMMON_API unsigned int SMB_CS_ReadSKFSignType(const char * pszSKFName, char * pszSignType, unsigned int *puiSignTypeLen);

#ifdef __cplusplus
}
#endif


#endif /*_SMB_CS_API_H_*/