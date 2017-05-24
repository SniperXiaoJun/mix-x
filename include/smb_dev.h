#ifndef __SMB_DEV_H__

#define __SMB_DEV_H__

#include <windows.h>
#include "smb_cs.h"
#include "SKFInterface.h"


// 证书(密钥类型标志) 可以做按位与操作
typedef enum _SMB_DEV_CERT_ALG_FLAG
{
	CERT_ALG_RSA_FLAG = 0x00000001,		// RSA证书
	CERT_ALG_SM2_FLAG = 0x00000002,		// SM2证书

}SMB_DEV_CERT_ALG_TYPE;

// 证书(签名|加密标志) 可以做按位与操作
typedef enum _SMB_DEV_CERT_USAGE_FLAG
{
	CERT_SIGN_FLAG = 0x00000001,		// 签名证书
	CERT_EX_FLAG = 0x00000002,		// 加密证书

}SMB_DEV_CERT_USAGE_FLAG;

// 证书(验证标志) 可以做按位与操作
typedef enum _SMB_DEV_CERT_VERIFY_FLAG
{
	CERT_NOT_VERIFY_FLAG = 0x00000000,		// 不验证
	CERT_VERIFY_TIME_FLAG = 0x00000001,		// 使用本地当前时间验证有效期
	CERT_VERIFY_CHAIN_FLAG = 0x00000002,		// 验证证书链以及签名
	CERT_VERIFY_CRL_FLAG = 0x00000004,		// 尚未实现

}SMB_DEV_CERT_VERIFY_FLAG;

// 验证结果
typedef enum _SMB_DEV_CERT_VERIFY_RESULT_FLAG
{
	CERT_VERIFY_RESULT_FLAG_OK = 0x00000000,		// 验证成功
	CERT_VERIFY_RESULT_TIME_INVALID = 0x00000001,		// 不在有效期
	CERT_VERIFY_RESULT_CHAIN_INVALID = 0x00000002,		// 证书链异常
	CERT_VERIFY_RESULT_SIGN_INVALID = 0x00000003,		// 非法用户证书
	CERT_VERIFY_RESULT_CRL_INVALID = 0x00000004,		// 尚未加入

}SMB_DEV_CERT_VERIFY_RESULT_FLAG;


typedef enum _SMB_DEV_CERT_FILTER_FLAG
{
	CERT_FILTER_FLAG_FALSE = 0x00000000,		// 不过滤
	CERT_FILTER_FLAG_TRUE = 0x00000001,		// 过滤
}SMB_DEV_CERT_FILTER_FLAG;


#ifdef __cplusplus
extern "C" {
#endif
	/*
	功能名称:	枚举SKF库
	函数名称:	SMB_DEV_EnumSKF
	输入参数:
	输出参数:
	pszSKFNames		 多字符串
	puiSKFNamesLen   多字符串长度
	返回值:
	失败：
	功能描述:	枚举SKF库
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_EnumSKF(char * pszSKFNames, unsigned int *puiSKFNamesLen);
	/*
	功能名称:	读取指定SKF库加载路径
	函数名称:	SMB_DEV_ReadSKFPath
	输入参数:	pszSKFName SKF库
	输出参数:
	pszDllPath		SKF库加载路径
	puiDllPathLen	长度
	返回值:
	失败：
	功能描述:	读取指定SKF库加载路径
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ReadSKFPath(const char * pszSKFName, char * pszDllPath, unsigned int *puiDllPathLen);


	/*
	功能名称:	读取指定SKF签名类型
	函数名称:	SMB_DEV_ReadSKFSignType
	输入参数:	pszSKFName SKF库
	输出参数:
	pszSignType		SKF库加载路径
	puiSignTypeLen	长度
	返回值:
	失败：
	功能描述:	读取指定SKF签名类型
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ReadSKFSignType(const char * pszSKFName, char * pszSignType, unsigned int *puiSignTypeLen);

	/*
	功能名称:	枚举证书
	函数名称:	SMB_DEV_EnumCertInternal
	输入参数:
	pszSKFName SKF库(NULL 代表全部SKF库)
	uiKeyFlag
	证书(密钥类型标志) 可以做按位与操作
	参见 SMB_DEV_CERT_ALG_FLAG
	uiSignFlag
	证书(签名|加密标志) 可以做按位与操作
	参见 SMB_DEV_CERT_SIGN_FLAG

	uiVerifyFlag
	证书(验证标志) 可以做按位与操作
	参见 SMB_DEV_CERT_VERIFY_FLAG
	输出参数:
	pvCertsValue	多证书串
	puiCertsLen		长度
	返回值:
	失败：
	功能描述:	枚举证书
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_EnumCertBySKF(const char * pszSKFName, void * pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);
	/*
	功能名称:	枚举设备
	函数名称:	SMB_DEV_EnumDev
	输入参数:
	输出参数:
	pszDevsName		多字符串，表示多个设备名,不同的设备名之间以0x00间隔，以0x0000表示多字符串结束
	puiDevsNameLen	返回多字符串长度
	返回值:
	失败：
	功能描述:	枚举设备
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_EnumDev(char *pszDevsName, unsigned int *puiDevsNameLen);

	/*
	功能名称:	枚举证书
	函数名称:	SMB_DEV_EnumCert
	输入参数:
	pszSKFName SKF库(NULL 代表全部SKF库)
	uiKeyFlag
	证书(密钥类型标志) 可以做按位与操作
	参见 SMB_DEV_CERT_ALG_FLAG
	uiSignFlag
	证书(签名|加密标志) 可以做按位与操作
	参见 SMB_DEV_CERT_SIGN_FLAG

	uiVerifyFlag
	证书(验证标志) 可以做按位与操作
	参见 SMB_DEV_CERT_VERIFY_FLAG
	输出参数:
	pvCertsValue	多证书串
	puiCertsLen		长度
	返回值:
	失败：
	功能描述:	枚举证书
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_EnumCert(const char *pszSKFName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	功能名称:	修改密码（签名证书代表设备）
	函数名称:	SMB_DEV_ChangePIN
	输入参数:
	pszDevName 设备名（使用者CN）
	uiPINType	类型
	pszOldPin 旧密码
	pszNewPin 新密码
	puiRetryCount 重试次数
	输出参数:
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ChangePIN(const char *pszDevName, unsigned int uiPINType, const char *pszOldPin, const char * pszNewPin, unsigned int *puiRetryCount);
	/*
	功能名称:	修改密码通过证书属性（签名证书代表设备）
	函数名称:	SMB_DEV_ChangePINByCertProperty
	输入参数:
	pCertProperty 证书属性  // SMC接口查找出来之后的结构体
	pszPIN	密码
	pbData  数据
	uiDataLen 长度
	输出参数:
	pSignature 签名值
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ChangePINByCertProperty(SMB_CS_CertificateAttr * pCertProperty, unsigned int uiPINType, const char * pszOldPin, const char * pszNewPin, unsigned int *puiRetryCount);


	typedef unsigned int (CallBackCfcaGetEncryptPIN)(void * param, unsigned char *pbRandom, unsigned int uiRandomLen, unsigned char *pbEncryptPIN, unsigned int *puiEncryptPINLen);


	typedef struct _OPST_HANDLE_ARGS {
		void * ghInst;
		void * hDev;
		void * hAPP;
		void * hCon;
	}OPST_HANDLE_ARGS;

	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignInitializeVerifyPINByCertProperty(SMB_CS_CertificateAttr * pCertProperty, unsigned int uiPINType, CallBackCfcaGetEncryptPIN GetEncryptPIN, OPST_HANDLE_ARGS * args, unsigned int *puiRetryCount);
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignDigestProcess(OPST_HANDLE_ARGS *args, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignFinalize(OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignDigestForHengBao(SMB_CS_CertificateAttr * pCertProperty, unsigned int uiPINType, CallBackCfcaGetEncryptPIN GetEncryptPIN, void * pArgs/*NULL is able*/, unsigned int *puiRetryCount, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);



	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignInitializeV2(SMB_CS_CertificateAttr * pCertProperty, OPST_HANDLE_ARGS *args);
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignDigestProcessV2(SMB_CS_CertificateAttr * pCertProperty, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignFinalizeV2(OPST_HANDLE_ARGS *args);

	COMMON_API unsigned int __stdcall SMB_DEV_ArgsGet(SMB_CS_CertificateAttr * pCertProperty, OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall SMB_DEV_ArgsPut(SMB_CS_CertificateAttr * pCertProperty, OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall SMB_DEV_ArgsClr();

	COMMON_API HINSTANCE __stdcall SMB_DEV_LoadLibrary(char * pszDllPath);

	/*
	功能名称:	获取设备信息
	函数名称:	SMB_DEV_GetDevInfoByCertProperty
	输入参数:
	pCertProperty 证书属性  // SMC接口查找出来之后的结构体
	输出参数:
	pDevInfo 设备信息
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_GetDevInfoByCertProperty(SMB_CS_CertificateAttr * pCertProperty, DEVINFO *pDevInfo);


	/*
	功能名称:	验证设备密码（签名证书代表设备）
	函数名称:	SMB_DEV_VerifyPIN
	输入参数:
	pszDevName 设备名称
	uiPINType 管理员/用户
	pszPIN	密码
	输出参数:
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	验证设备密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_VerifyPIN(const char *pszDevName, unsigned int uiPINType, const char *pszPin, unsigned int *puiRetryCount);
	/*
	功能名称:	验证设备密码通过证书属性（签名证书代表设备）
	函数名称:	SMB_DEV_VerifyPINByCertProperty
	输入参数:
	pCertProperty 证书属性  // SMC接口查找出来之后的结构体
	uiPINType 管理员/用户
	pszPIN	密码
	输出参数:
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	验证设备密码通过证书属性
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_VerifyPINByCertProperty(SMB_CS_CertificateAttr * pCertProperty, unsigned int uiPINType, const char * pszPin, unsigned int *puiRetryCount);


	/*
	功能名称:	SM2证书签名
	函数名称:	SMB_DEV_SM2SignDigest
	输入参数:
	pCertProperty 证书属性  // SMC接口查找出来之后的结构体
	pszPIN	密码
	pbData  数据
	uiDataLen 长度
	输出参数:
	pSignature 签名值
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignDigest(SMB_CS_CertificateAttr *pCertProperty, const char *pszPIN, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature, unsigned int *puiRetryCount);

	COMMON_API unsigned int __stdcall SMB_DEV_SM2SignDigestV2(
		SMB_CS_CertificateAttr *pCertProperty,
		const char *pszPIN,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature, unsigned int *puiRetryCount);


	/*
	功能名称:	SM2公钥验证
	函数名称:	SMB_DEV_SM2VerifyDigest
	输入参数:
	pszDevName 设备名（使用者CN）
	pSM2PubKeyBlob	公钥
	pbData  数据
	uiDataLen 长度
	pSignature 签名值
	输出参数:
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB* pSM2PubKeyBlob, BYTE *pbData, ULONG  uiDataLen, PECCSIGNATUREBLOB pSignature);


	/*
	功能描述:	验证证书的合法性
	参数:
	pszSKFName SKF库(NULL 代表全部SKF库)
	uiVerifyFlag
	证书(验证标志) 可以做按位与操作
	参见 SMB_DEV_CERT_VERIFY_FLAG
	pbCert[IN]:  输入证书内容,DER编码
	uiCertLen[IN]:输入证书内容长度。
	返回值		0：  成功。
	其他： 错误码

	*/
	COMMON_API unsigned int __stdcall SMB_DEV_VerifyCert(unsigned int uiFlag, unsigned int uiAlgType, BYTE* pbCert, unsigned int uiCertLen);

	/*
	功能描述:	验证根证书的合法性
	参数:
	uiVerifyFlag
	(验证标志) 可以做按位与操作
	uiVerifyFlag
	证书(验证标志) 可以做按位与操作
	参见 SMB_DEV_CERT_VERIFY_FLAG
	pbCert[IN]:  输入证书内容,DER编码
	uiCertLen[IN]:输入证书内容长度。
	返回值		0：  成功。
	其他： 错误码

	*/
	COMMON_API unsigned int __stdcall SMB_DEV_VerifyRootCert(unsigned int uiVerifyFlag, unsigned int uiAlgType, BYTE* pbCert, unsigned int uiCertLen);


	/*
	功能描述:	证书获取属性信息
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	输出参数:
	pCertProperty	证书属性
	返回值		0：  成功。
	其他： 错误码

	*/
	COMMON_API unsigned int __stdcall SMB_DEV_CertGetProperty(BYTE* pbCert, unsigned int uiCertLen, SMB_CS_CertificateAttr * pCertProperty);

	/*
	功能描述:	显示证书
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_UIDlgViewContext(BYTE* pbCert, unsigned int uiCertLen);

	/*
	功能描述:	清空存储区里的证书
	输入参数:
	uiStoreID ：
	DEFAULT_SMC_STORE_SM2_ROOT_ID 1                // 根
	DEFAULT_SMC_STORE_SM2_USER_ID 2                // 用户
	DEFAULT_SMC_STORE_SM2_OTHERS_ID 3              // 其他
	DEFAULT_SMC_STORE_SM2_CRL_ID 4                 // 吊销列表
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ClearStore(unsigned int uiStoreID);

	/*
	功能描述:	导入根证书
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	输出参数：
	puiAlgType 算法类型
	返回值		0：  成功。

	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_ImportCaCert(BYTE * pbCert, unsigned int uiCertLen, unsigned int * puiAlgType);

	/*
	功能描述:	是否是根证书
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_IsSM2RootCert(BYTE* pbCert, unsigned int uiCertLen, unsigned int * bIRoot);

	/*
	功能描述:	查找上级CA证书
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	输出参数：
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_FindSM2CACert(BYTE* pbCert, unsigned int uiCertLen,
		BYTE* pbCACert, unsigned int * uiCACertLen
	);

	/*
	功能描述:	查找SKF驱动
	输入参数:
	pszSKFName: 名称
	szVersion:版本号
	输出参数：
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_FindSKFDriver(const char * pszSKFName, char * szVersion);


	/*
	功能描述:	打印错误日志（内部测试使用必须同时打开日志记录）
	*/
	COMMON_API void SMB_DEV_PrintErrorMsg();

	/*
	功能描述:	通过证书描述属性获取加密证书
	*/
	COMMON_API unsigned int __stdcall SMB_DEV_FindEnCertificateByCertDescProperty(
		_In_ SMB_CS_CertificateAttr * pCertDescProperty, _Out_ unsigned char * pbCert, _Inout_ unsigned int * puiCertLen
	);

	COMMON_API unsigned int __stdcall SMB_DEV_SM2GetAgreementKey(
		_In_ SMB_CS_CertificateAttr * pCertProperty,
		_In_ ULONG ulAlgId,
		_Out_ ECCPUBLICKEYBLOB *pTempECCPubKeyBlobA,
		_In_ BYTE* pbIDA,
		_In_ ULONG ulIDALen,
		_In_ ECCPUBLICKEYBLOB *pECCPubKeyBlobB,
		_In_ ECCPUBLICKEYBLOB *pTempECCPubKeyBlobB,
		_In_ BYTE* pbIDB,
		_In_ ULONG ulIDBLen,
		_Out_ BYTE *pbAgreementKey,
		_Inout_ ULONG *pulAgreementKeyLen,
		_In_ const char * pszPIN,
		_Inout_ ULONG * puiRetryCount);

	COMMON_API unsigned int __stdcall SMB_DEV_SM2GetAgreementKeyEx(
		_In_ BYTE* pbCert,
		_In_ unsigned int uiCertLen,
		_In_ int uiAlgId,
		_Out_ BYTE* pbTempECCPubKeyBlobA,
		_Inout_ int *puiTempECCPubKeyBlobALen,
		_In_ BYTE* pbIDA,
		_In_ int uiIDALen,
		_In_ BYTE* pbECCPubKeyBlobB,
		_In_ int  uiECCPubKeyBlobBLen,
		_In_ BYTE* pbTempECCPubKeyBlobB,
		_In_ int  uiTempECCPubKeyBlobBLen,
		_In_ BYTE* pbIDB,
		_In_ int uiIDBLen,
		_Out_ BYTE *pbAgreementKey,
		_Inout_ int *puiAgreementKeyLen,
		_In_ const char * pszPIN,
		_Inout_ int * puiRetryCount);

#ifdef __cplusplus
}
#endif



#endif