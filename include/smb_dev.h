#ifndef __SMB_DEV_H__

#define __SMB_DEV_H__

#include <windows.h>
#include "smb_cs.h"
#include "SKFInterface.h"

#ifdef __cplusplus
extern "C" {
#endif

	/*
	功能名称:	通过SKF枚举证书
	函数名称:	SMB_DEV_EnumCertBySKF
	输入参数:
		pszSKFName SKF库(必须指定)
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
	返回值: 0:成功 其他:错误码
	*/
	COMMON_API unsigned int SMB_DEV_EnumCertBySKF(const char*pszSKFName, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	功能名称:	枚举证书
	函数名称:	SMB_DEV_EnumCert
	输入参数:
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
	返回值: 0:成功 其他:错误码
	*/
	COMMON_API unsigned int SMB_DEV_EnumCert(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	功能名称:	修改密码通过证书属性（签名证书代表设备）
	函数名称:	SMB_DEV_ChangePINByCertAttr
	输入参数:
	pCertAttr 证书属性// SMC接口查找出来之后的结构体
	pszPIN	密码
	pbData数据
	uiDataLen 长度
	输出参数:
	pSignature 签名值
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int SMB_DEV_ChangePINByCertAttr(SMB_CS_CertificateAttr *pCertAttr, unsigned int uiPINType, const char*pszOldPin, const char*pszNewPin, ULONG *puiRetryCount);

	/*
	通过证书描述属性获取加密证书
	*/
	COMMON_API unsigned int SMB_DEV_FindEnCertificateByCertAttr(
		IN SMB_CS_CertificateAttr *pCertAttr, OUT unsigned char *pbCert, IN OUT unsigned int *puiCertLen
	);

	/*
	功能名称:	获取设备信息
	函数名称:	SMB_DEV_GetDevInfoByCertAttr
	输入参数:
	pCertAttr 证书属性// SMC接口查找出来之后的结构体
	输出参数:
	pDevInfo 设备信息
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int SMB_DEV_GetDevInfoByCertAttr(SMB_CS_CertificateAttr*pCertAttr, DEVINFO *pDevInfo);

	/*
	功能名称:	验证设备密码通过证书属性（签名证书代表设备）
	函数名称:	SMB_DEV_VerifyPINByCertAttr
	输入参数:
	pCertAttr 证书属性// SMC接口查找出来之后的结构体
	uiPINType 管理员/用户
	pszPIN	密码
	输出参数:
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	验证设备密码通过证书属性
	*/
	COMMON_API unsigned int SMB_DEV_VerifyPINByCertAttr(SMB_CS_CertificateAttr*pCertAttr, unsigned int uiPINType, char*pszPin, ULONG *puiRetryCount);

	/*
	功能名称:	SM2证书签名
	函数名称:	SMB_DEV_SM2Sign
	输入参数:
	pCertAttr 证书属性// SMB接口查找出来之后的结构体
	pszPIN	密码
	pbData数据
	uiDataLen 长度
	输出参数:
	pSignature 签名值
	puiRetryCount 重试次数
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int SMB_DEV_SM2Sign(
		SMB_CS_CertificateAttr *pCertAttr,
		char *pszPIN,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount);

	/*
	功能名称:	SM2公钥验证
	函数名称:	SMB_DEV_SM2VerifyDigest
	输入参数:
	pszDevName 设备名（使用者CN）
	pSM2PubKeyBlob	公钥
	pbData数据
	uiDataLen 长度
	pSignature 签名值
	输出参数:
	返回值:
	失败：
	功能描述:	修改密码
	*/
	COMMON_API unsigned int SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB *pSM2PubKeyBlob, BYTE *pbData, ULONG uiDataLen, PECCSIGNATUREBLOB pSignature);


	/*
	功能描述:	显示证书
	输入参数:
	pbCert[IN]:		输入证书内容,DER编码
	uiCertLen[IN]:	输入证书内容长度。
	返回值		0：成功。
	其他：		错误码
	*/
	COMMON_API unsigned int SMB_UI_ShowUI(BYTE *pbCert, unsigned int uiCertLen);

	/*
	功能描述:	查找SKF驱动
	输入参数:
	pszSKFName: 名称
	szVersion:版本号
	输出参数：
	返回值		0：  成功。
	其他：		错误码
	*/
	COMMON_API unsigned int SMB_DEV_FindSKFDriver(const char * pszSKFName, char * szVersion);


	COMMON_API unsigned int SMB_DEV_SM2GetAgreementKey(
		IN SMB_CS_CertificateAttr*pCertAttr,
		IN ULONG ulAlgId,
		OUT ECCPUBLICKEYBLOB *pTempECCPubKeyBlobA,
		IN BYTE *pbIDA,
		IN ULONG ulIDALen,
		IN ECCPUBLICKEYBLOB *pECCPubKeyBlobB,
		IN ECCPUBLICKEYBLOB *pTempECCPubKeyBlobB,
		IN BYTE *pbIDB,
		IN ULONG ulIDBLen,
		OUT BYTE *pbAgreementKey,
		IN OUT ULONG *pulAgreementKeyLen,
		IN char*pszPIN,
		IN OUT ULONG*puiRetryCount);

	COMMON_API unsigned int SMB_DEV_SM2GetAgreementKeyEx(
		IN BYTE *pbCert,
		IN unsigned int uiCertLen,
		IN int uiAlgId,
		OUT BYTE *pbTempECCPubKeyBlobA,
		IN OUT int *puiTempECCPubKeyBlobALen,
		IN BYTE *pbIDA,
		IN int uiIDALen,
		IN BYTE *pbECCPubKeyBlobB,
		IN int uiECCPubKeyBlobBLen,
		IN BYTE *pbTempECCPubKeyBlobB,
		IN int uiTempECCPubKeyBlobBLen,
		IN BYTE *pbIDB,
		IN int uiIDBLen,
		OUT BYTE *pbAgreementKey,
		IN OUT ULONG *puiAgreementKeyLen,
		IN const char*pszPIN,
		IN OUT ULONG*puiRetryCount);


	/*
	-----------------------------------------------------------------------------------------------------
	未实现函数声明
	-----------------------------------------------------------------------------------------------------
	*/

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
	COMMON_API unsigned int SMB_DEV_EnumDev(char *pszDevsName, unsigned int *puiDevsNameLen);

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
	COMMON_API unsigned int SMB_DEV_ChangePIN(const char *pszDevName, unsigned int uiPINType, const char *pszOldPin, const char*pszNewPin, ULONG *puiRetryCount);

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
	COMMON_API unsigned int SMB_DEV_VerifyPIN(const char *pszDevName, unsigned int uiPINType, char *pszPin, ULONG *puiRetryCount);

	/*
	
	*/
	COMMON_API unsigned int SMB_DEV_SM2SignByCertAttr(
		SMB_CS_CertificateAttr *pCertAttr,
		char *pszPIN,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount);

	COMMON_API unsigned int SMB_DEV_SM2SignProcessByCertAttr(
		SMB_CS_CertificateAttr*pCertAttr,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature);


#ifdef __cplusplus
}
#endif



#endif