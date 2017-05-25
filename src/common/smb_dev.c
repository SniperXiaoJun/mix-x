﻿

#include "smb_dev.h"
#include "stdio.h"
#include <string.h>
#include <WinCrypt.h>
#include "openssl_func_def.h"
#include "o_all_type_def.h"
#include "FILE_LOG.h"
#include "SKFInterface.h"
#include "SKFError.h"
#pragma warning(disable:4996)

#if USE_SELF_MUTEX
#include "SDSCMutex.h"
static char mutex_buffer[25] = "mutex_smc_interface";
HANDLE hMutex = 0;
#endif

#define REG_ROOT_KEY HKEY_LOCAL_MACHINE
#define REG_SUB_KEY_PREFIX "SOFTWARE\\Microsoft\\Cryptography\\Defaults\\SKF"
#define REG_VALUE_PATH_KEYNAME "path"
#define REG_VALUE_SIGNTYPE_KEYNAME "signtype"
#define REG_CURRENT_SKF "WDSKF"

#define SM2_ALG_BYTES "\x2a\x86\x48\xce\x3d\x02\x01"

#define FUNC_NAME_DECLARE(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) \
	pSKF_##FUNC_NAME FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX=NULL

#define FUNC_NAME_INIT(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) (##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_"#FUNC_NAME); \
	if(!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{ \
	ulRet = EErr_SMB_DLL_PATH; \
	goto err; \
}\
	else \
{ \
} 

#define FUNC_NAME_INIT_GetContainerType(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) \
	(##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_"#FUNC_NAME); \
	if (!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{\
	(##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_GetContianerType"); \
}\
	if(!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{ \
	ulRet = EErr_SMB_DLL_PATH; \
	goto err; \
}\
	else \
{ \
} 

typedef ULONG (DEVAPI *pSKF_EnumDev)(BOOL bPresent, LPSTR szNameList, ULONG *puiSize);
typedef ULONG (DEVAPI *pSKF_ConnectDev)(LPSTR szName, DEVHANDLE *phDev);
typedef ULONG (DEVAPI *pSKF_DisConnectDev)(DEVHANDLE hDev);
typedef ULONG (DEVAPI *pSKF_ChangePIN)(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *puiRetryCount);
typedef ULONG (DEVAPI *pSKF_OpenApplication)(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
typedef ULONG (DEVAPI *pSKF_CloseApplication)(HAPPLICATION hApplication);
typedef ULONG (DEVAPI *pSKF_EnumApplication)(DEVHANDLE hDev, LPSTR szAppName,ULONG *puiSize);
typedef ULONG (DEVAPI *pSKF_EnumContainer)(HAPPLICATION hApplication,LPSTR szContainerName,ULONG *puiSize);
typedef ULONG (DEVAPI *pSKF_OpenContainer)(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer);
typedef ULONG (DEVAPI *pSKF_CloseContainer)(HCONTAINER hContainer);
typedef ULONG (DEVAPI *pSKF_VerifyPIN)(HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *puiRetryCount);
typedef ULONG (DEVAPI *pSKF_ExportCertificate)(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *puiCertLen);
typedef ULONG (DEVAPI *pSKF_GetContainerType)(HCONTAINER hContainer, ULONG *puiContainerType);
typedef ULONG (DEVAPI *pSKF_ECCSignData)(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG (DEVAPI *pSKF_ECCVerify)(DEVHANDLE hDev , ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG (DEVAPI *pSKF_ExtECCVerify)(DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG (DEVAPI *pSKF_GetDevInfo)(DEVHANDLE hDev, DEVINFO *pDevInfo);
typedef ULONG (DEVAPI *pSKF_LockDev)(DEVHANDLE hDev, ULONG ulTimeOut);
typedef ULONG (DEVAPI *pSKF_UnlockDev)(DEVHANDLE hDev);

typedef ULONG (DEVAPI *pSKF_GenRandom)(DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);
typedef ULONG (DEVAPI *pSKF_Transmit)(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen,BYTE* pbData, ULONG* pulDataLen);

typedef ULONG (DEVAPI *pSKF_GenerateAgreementDataWithECC)(HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle);

typedef ULONG(DEVAPI *pSKF_GenerateAgreementDataWithECCEx)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);

typedef ULONG(DEVAPI *pSKF_GenerateAgreementDataAndKeyWithECCEx)(HANDLE hContainer, ULONG ulAlgId,
	ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
	BYTE *pbAgreementKey,
	ULONG *pulAgreementKeyLen);

//7.6.22 ECC计算会话密钥 扩展接口: 返回协商后的密钥
typedef ULONG (DEVAPI *pSKF_GenerateKeyWithECCEx)(HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	BYTE* pbID, ULONG ulIDLen, 
	BYTE *pbAgreementKey, ULONG *pulAgreementKeyLen);


// 最大加载SKF DLL接口个数
#define MAX_SKF_DLL_LOAD 4

// 最大设备个数
#define MAX_SKF_CERT 1024


unsigned int SMB_DEV_ChangePINByCertAttr(SMB_CS_CertificateAttr * pCertAttr, unsigned int ulPINType, char * pszOldPin, char * pszNewPin, unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{
		ulRet = func_ConnectDev(pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev, pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_ChangePIN(hAPP, ulPINType, pszOldPin, pszNewPin, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	return ulRet;
}

unsigned int SMB_DEV_GetDevInfoByCertProperty(SMB_CS_CertificateAttr * pCertAttr, DEVINFO *pDevInfo)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	// 读取路径
	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT(func_, GetDevInfo, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	// 获取设备信息
	{


		ulRet = func_ConnectDev(pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_GetDevInfo(hDev, pDevInfo);
		if (0 != ulRet)
		{
			goto err;
		}

		if (hDev)
		{
#if USE_SELF_MUTEX
			SDSCReleaseMutex(hMutex);
#else
			func_UnlockDev(hDev);
#endif
			ulRet = func_DisConnectDev(hDev); hDev = NULL;
		}
	}


err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_VerifyPINByCertProperty(SMB_CS_CertificateAttr * pCertAttr, unsigned int ulPINType, char * pszPin, unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{


		ulRet = func_ConnectDev(pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev, pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP, ulPINType, pszPin, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_SM2SignDigest(
	SMB_CS_CertificateAttr *pCertAttr,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;


	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	unsigned int signTypeLen = BUFFER_LEN_1K;
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

	// there may be fail, so don't judge return value
	SMB_CS_ReadSKFSignType(pCertAttr->stSKFName.data, signTypeValue, &signTypeLen);

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, ECCSignData, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{
		ulRet = func_ConnectDev(pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}


		ulRet = func_OpenApplication(hDev, pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, pCertAttr->stContainerName.data, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		if (0 == memcmp("data", signTypeValue, 4))
		{
			ulRet = func_ECCSignData(hCon, pbData, uiDataLen, pSignature);
		}
		else
		{
			ulRet = func_ECCSignData(hCon, pbDigest, uiDigestLen, pSignature);
		}

		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseContainer(hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}

unsigned int SMB_DEV_EnumCertBySKF(const char * pszSKFName, void * pvCertsValue, unsigned int *puiCertsLen, unsigned int ulKeyFlag, unsigned int ulSignFlag, unsigned int ulVerifyFlag, unsigned int ulFilterFlag)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;
	int i = 0; // certs

	char * data_value = NULL;
	char * pTmp = NULL;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	char szConNames[BUFFER_LEN_1K] = { 0 };
	ULONG ulConSize = BUFFER_LEN_1K;

	HAPPLICATION hAPP = NULL;
	char szAppNames[BUFFER_LEN_1K] = { 0 };
	ULONG ulAppsSize = BUFFER_LEN_1K;

	char szDevs[BUFFER_LEN_1K];
	ULONG ulDevSize = BUFFER_LEN_1K;

	char * ptrContainer = NULL;
	char * ptrApp = NULL;
	char * ptrDev = NULL;

	unsigned int ulOutLen = 0;

	SMB_CS_CertificateContext * pCertCtx = NULL;

	DEVHANDLE hDev = NULL;

	char buffer_zero[BUFFER_LEN_1K] = { 0 };


	pTmp = (char *)malloc(BUFFER_LEN_1K * 4);
	data_value = (char *)malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	ulRet = SMB_CS_ReadSKFPath(pszSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, GetDevInfo, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );


	pCertCtx = (SMB_CS_CertificateContext *)data_value;
	i = 0;
	ulOutLen = 0;
	ulRet = func_EnumDev(TRUE, szDevs, &ulDevSize);
	if (0 != ulRet)
	{
		goto err;
	}

	for (ptrDev = szDevs; (ptrDev < szDevs + ulDevSize) && *ptrDev != 0;)
	{
		DEVINFO devInfo;
		hDev = NULL;

		ulRet = func_ConnectDev(ptrDev, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		//ulRet = func_GetDevInfo(hDev,&devInfo);
		//if (0 != ulRet)
		//{
		//	goto err;
		//}

		ulAppsSize = BUFFER_LEN_1K;

		ulRet = func_EnumApplication(hDev, szAppNames, &ulAppsSize);

		if (0 != ulRet)
		{
			goto err;
		}

		for (ptrApp = szAppNames; (ptrApp < szAppNames + ulAppsSize) && *ptrApp != 0;)
		{
			ulConSize = BUFFER_LEN_1K;

			ulRet = func_OpenApplication(hDev, ptrApp, &hAPP);

			if (0 != ulRet)
			{
				goto err;
			}

			ulRet = func_EnumContainer(hAPP, szConNames, &ulConSize);

			//while (ulRet == 0 && 0 == memcmp(buffer_zero,szConNames,ulConSize > BUFFER_LEN_1K? BUFFER_LEN_1K:ulConSize))
			//{
			//	ulConSize = BUFFER_LEN_1K;
			//	ulRet = func_EnumContainer(hAPP,szConNames,&ulConSize);
			//}

			if (0 != ulRet)
			{
				goto err;
			}

			if (0 == ulConSize)
			{
				ulRet = EErr_SMB_DLL_PATH;
				goto err;
			}

			for (ptrContainer = szConNames; (ptrContainer < szConNames + ulConSize) && *ptrContainer != 0; )
			{
				HCONTAINER hCon = NULL;
				ULONG ulContainerType = 0;



				ulRet = func_OpenContainer(hAPP, ptrContainer, &hCon);
				if (ulRet)
				{
					goto err;
				}

				//1表示为RSA容器，为2表示为ECC容器
				ulRet = func_GetContainerType(hCon, &ulContainerType);
				if (ulRet)
				{
					goto err;
				}

				if (!(ulKeyFlag & ulContainerType))
				{
					// next Container
					ptrContainer += strlen(ptrContainer);
					ptrContainer += 1;
					continue;
				}

				if (CERT_SIGN_FLAG & ulSignFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K * 4;

					nValueLen = BUFFER_LEN_1K * 4;

					ulRet = func_ExportCertificate(hCon, TRUE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (ulVerifyFlag)
						{
							ulRet = SMB_DEV_VerifyCert(ulVerifyFlag, ulContainerType, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (CERT_FILTER_FLAG_TRUE == ulFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
								else
								{
									switch (ulRet) {
									case EErr_SMB_VERIFY_TIME:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_TIME_INVALID;
										break;
									case EErr_SMB_NO_CERT_CHAIN:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									case EErr_SMB_VERIFY_CERT:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_SIGN_INVALID;
										break;
									default:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									}
								}

							}
							else
							{
								pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_FLAG_OK;
							}

						}

						ulOutLen += nValueLen + sizeof(SMB_CS_CertificateContext);

						pCertCtx->nValueLen = nValueLen;

						pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

						memcpy(pCertCtx->pbValue, pTmp, nValueLen);

						strcpy(pCertCtx->stProperty.szSKFName, pszSKFName);

						strcpy(pCertCtx->stProperty.szDeviceName, ptrDev);

						strcpy(pCertCtx->stProperty.szApplicationName, ptrApp);

						strcpy(pCertCtx->stProperty.szContainerName, ptrContainer);

						pCertCtx->stProperty.bSignType = TRUE;

						pCertCtx->stProperty.nType = ulContainerType;

						pCertCtx = (BYTE*)pCertCtx + nValueLen + sizeof(SMB_CS_CertificateContext);

						i++;
					}
					else if (0x0A00001C == ulRet)
					{
						// 证书未发现
						ulRet = 0;
					}
					else
					{

					}
				}

				if (CERT_EX_FLAG & ulSignFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K * 4;

					nValueLen = BUFFER_LEN_1K * 4;

					ulRet = func_ExportCertificate(hCon, FALSE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (ulVerifyFlag)
						{
							ulRet = SMB_DEV_VerifyCert(ulVerifyFlag, ulContainerType, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (CERT_FILTER_FLAG_TRUE == ulFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
								else
								{
									switch (ulRet) {
									case EErr_SMB_VERIFY_TIME:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_TIME_INVALID;
										break;
									case EErr_SMB_NO_CERT_CHAIN:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									case EErr_SMB_VERIFY_CERT:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_SIGN_INVALID;
										break;
									default:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									}
								}

							}
							else
							{
								pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_FLAG_OK;
							}
						}

						ulOutLen += nValueLen + sizeof(SMB_CS_CertificateContext);

						pCertCtx->nValueLen = nValueLen;

						pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

						memcpy(pCertCtx->pbValue, pTmp, nValueLen);

						strcpy(pCertCtx->stProperty.szSKFName, pszSKFName);

						strcpy(pCertCtx->stProperty.szDeviceName, ptrDev);

						strcpy(pCertCtx->stProperty.szApplicationName, ptrApp);

						strcpy(pCertCtx->stProperty.szContainerName, ptrContainer);

						pCertCtx->stProperty.bSignType = FALSE;

						pCertCtx->stProperty.nType = ulContainerType;

						pCertCtx = (BYTE*)pCertCtx + nValueLen + sizeof(SMB_CS_CertificateContext);

						i++;
					}
					else if (0x0A00001C == ulRet)
					{
						// 证书未发现
						ulRet = 0;
					}
					else
					{

					}
				}

				ulRet = func_CloseContainer(hCon);
				if (ulRet)
				{
					goto err;
				}

				// next Container
				ptrContainer += strlen(ptrContainer);
				ptrContainer += 1;
			}

			ulRet = func_CloseApplication(hAPP);
			if (0 != ulRet)
			{
				goto err;
			}

			// next Application
			ptrApp += strlen(ptrApp);
			ptrApp += 1;
		}


#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}

		ptrDev += strlen(ptrDev);
		ptrDev += 1;
	}

	ulRet = -1;

	if (NULL == pvCertsValue)
	{
		*puiCertsLen = ulOutLen;

		ulRet = 0;

		goto err;
	}
	else if (*puiCertsLen < ulOutLen)
	{
		*puiCertsLen = ulOutLen;

		ulRet = EErr_SMB_MEM_LES;

		goto err;
	}
	else
	{
		memcpy(pvCertsValue, data_value, ulOutLen);

		for (pCertCtx = (SMB_CS_CertificateContext *)pvCertsValue; (char *)pCertCtx < (char *)pvCertsValue + ulOutLen;)
		{
			pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

			SMB_DEV_CertGetProperty(pCertCtx->pbValue, pCertCtx->nValueLen, &(pCertCtx->stProperty));

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
		}

		*puiCertsLen = ulOutLen;
		ulRet = 0;
	}

err:
	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	if (pTmp)
	{
		free(pTmp);
	}

	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}

//LIQIANGQIANG

#if 0


unsigned int SMB_DEV_EnumCertByDev(const char *pszDevName, void * pvCertsValue, unsigned int *puiCertsLen, unsigned int ulKeyFlag, unsigned int ulSignFlag, unsigned int ulVerifyFlag, unsigned int ulFilterFlag)
{
	unsigned int ulRet = 0;

	char * data_value;
	unsigned int data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;
	SMB_CS_CertificateContext * pCertCtx = NULL;

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	memset(data_value, 0, data_len);

	// 遍历全部
	ulRet = SMB_DEV_EnumCert(NULL, data_value, &data_len, ulKeyFlag, ulSignFlag, ulVerifyFlag, ulFilterFlag);

	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, data_len);


	if (ulRet)
	{
		*puiCertsLen = data_len;
		goto err;
	}

	// 非空  拷贝
	if (pszDevName && strlen(pszDevName))
	{
		unsigned int ulLenTmp = 0;
		char * pTmp = (char *)malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);
		char * pszDeviceName = NULL;

		// find pszDevName's szDeviceName
		for (pCertCtx = (SMB_CS_CertificateContext *)data_value; pCertCtx < data_value + data_len;)
		{
			if (0 == strcmp(pCertCtx->stProperty.szCommonName, pszDevName))
			{
				pszDeviceName = pCertCtx->stProperty.szDeviceName;
				break;
			}

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
		}

		// not find
		if (pCertCtx >= data_value + data_len || NULL == pszDeviceName)
		{
			ulRet = 0;
			*puiCertsLen = 0;

			goto err;
		}

		// szDeviceName equal copy, no equal no copy
		for (pCertCtx = (SMB_CS_CertificateContext *)data_value; pCertCtx < data_value + data_len;)
		{
			if (0 == strcmp(pCertCtx->stProperty.szDeviceName, pszDeviceName))
			{
				memcpy(pTmp + ulLenTmp, pCertCtx, pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext));

				ulLenTmp += pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
			}
			else
			{
				// nothing to do
			}

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
		}

		data_len = ulLenTmp;
		memcpy(data_value, pTmp, ulLenTmp);
		free(pTmp);
	}

	ulRet = -1;

	if (NULL == pvCertsValue)
	{
		*puiCertsLen = data_len;

		ulRet = 0;

		goto err;
	}
	else if (*puiCertsLen < data_len)
	{
		*puiCertsLen = data_len;

		ulRet = EErr_SMB_MEM_LES;

		goto err;
	}
	else
	{
		memcpy(pvCertsValue, data_value, data_len);


		for (pCertCtx = (SMB_CS_CertificateContext *)pvCertsValue; (char *)pCertCtx < (char *)pvCertsValue + data_len;)
		{
			pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
		}

		*puiCertsLen = data_len;
		ulRet = 0;
	}

err:
	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}

unsigned int SMB_DEV_EnumDev(char * pszDevsName,unsigned int *puiDevsNameLen)
{
	unsigned int ulRet = -1;

	char * data_value;
	unsigned int data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;
	unsigned int ulOutLen = 0;

	SMB_CS_CertificateContext * pCertCtx = NULL;

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	memset(data_value, 0, data_len);

	// 计算长度
	ulRet = SMB_DEV_EnumCertInternal(NULL,data_value,&data_len,CERT_ALG_SM2_FLAG,CERT_SIGN_FLAG,0, 0);
	if(ulRet)
	{
		goto err;
	}

	for (pCertCtx = (SMB_CS_CertificateContext *)data_value;pCertCtx < data_value + data_len;)
	{
		ulOutLen += strlen(pCertCtx->stProperty.szCommonName) + 1;

		pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext) ;
	}

	if (ulOutLen)
	{
		ulOutLen += 1;
	}


	// 赋值
	pCertCtx = (SMB_CS_CertificateContext *)data_value;

	if (NULL == pszDevsName)
	{
		*puiDevsNameLen = ulOutLen;
		ulRet = 0;
	}
	else if(*puiDevsNameLen < ulOutLen)
	{
		*puiDevsNameLen = ulOutLen;
		ulRet = EErr_SMB_MEM_LES;
	}
	else
	{
		*puiDevsNameLen = ulOutLen;

		memset(pszDevsName, 0, ulOutLen);

		ulOutLen = 0;

		for (pCertCtx = (SMB_CS_CertificateContext *)data_value;pCertCtx < data_value + data_len;)
		{
			strcpy((char *)pszDevsName + ulOutLen, pCertCtx->stProperty.szCommonName);

			ulOutLen += strlen(pCertCtx->stProperty.szCommonName) + 1;

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext) ;
		}
		ulRet = 0;
	}

err:
	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}


unsigned int SMB_DEV_ChangePIN(const char *pszDevName,unsigned int ulPINType ,const char * pszOldPin,const char * pszNewPin,unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	char * data_value;
	unsigned int data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	SMB_CS_CertificateContext * pCertCtx = NULL;

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	memset(data_value, 0, data_len);

	ulRet = SMB_DEV_EnumCertInternal(NULL,data_value,&data_len,CERT_ALG_SM2_FLAG,CERT_SIGN_FLAG,0,0);

	if(ulRet)
	{
		goto err;
	}

	for (pCertCtx = (SMB_CS_CertificateContext *)data_value;pCertCtx < data_value + data_len;)
	{
		if (0 == strcmp(pCertCtx->stProperty.szCommonName,pszDevName))
		{
			break;
		}

		pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext) ;
	}

	if (pCertCtx >= data_value + data_len)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}


	ulRet = SMB_CS_ReadSKFPath(pCertCtx->stProperty.szSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	{
		ulRet = func_ConnectDev(pCertCtx->stProperty.szDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev,pCertCtx->stProperty.szApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_ChangePIN(hAPP,ulPINType , pszOldPin,pszNewPin,puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}

unsigned int SMB_DEV_VerifyPIN(const char *pszDevName,unsigned int ulPINType ,const char * pszPin,unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	char * data_value;
	unsigned int data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	SMB_CS_CertificateContext * pCertCtx = NULL;

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	memset(data_value, 0, data_len);

	ulRet = SMB_DEV_EnumCertInternal(NULL,data_value,&data_len,CERT_ALG_SM2_FLAG,CERT_SIGN_FLAG,0,0);

	if(ulRet)
	{
		goto err;
	}

	for (pCertCtx = (SMB_CS_CertificateContext *)data_value;pCertCtx < data_value + data_len;)
	{
		if (0 == strcmp(pCertCtx->stProperty.szCommonName,pszDevName))
		{
			break;
		}

		pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext) ;
	}

	if (pCertCtx >= data_value + data_len)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}


	ulRet = SMB_CS_ReadSKFPath(pCertCtx->stProperty.szSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	{

		ulRet = func_ConnectDev(pCertCtx->stProperty.szDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev,pCertCtx->stProperty.szApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP,ulPINType , pszPin,puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}


err:
	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}




#if defined(VERIFY_PIN_USE_ENCRYPT)

#include "modp_b64.h"


COMMON_API unsigned int SMB_DEV_SM2SignInitializeV2(SMB_CS_CertificateAttr * pCertAttr, OPST_HANDLE_ARGS * args)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_DECLARE(func_, GenRandom, );
	FUNC_NAME_DECLARE(func_, Transmit, );
	

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	FUNC_NAME_INIT(func_, ECCSignData,);

	FUNC_NAME_INIT(func_, GenRandom, );
	FUNC_NAME_INIT(func_, Transmit, );

	{
		unsigned char bufferRandom[8] = {0};
		ULONG bufferRandomLen = 8;

		unsigned char szEncrypPin[BUFFER_LEN_1K] = {0};
		unsigned int uiEncryptPinLen = BUFFER_LEN_1K;


		ulRet = func_ConnectDev(pCertAttr->stDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
		ulRet = func_OpenApplication(hDev,pCertAttr->stApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);

		ulRet = func_OpenContainer(hAPP, pCertAttr->stContainerName, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}
		else
		{
			OPST_HANDLE_ARGS * handleArgs = args;

			if (handleArgs)
			{
				handleArgs->ghInst = ghInst;
				handleArgs->hDev = hDev;
				handleArgs->hAPP = hAPP;
				handleArgs->hCon = hCon;

				if(hCon)
				{

				}
				else
				{
					ulRet = EErr_SMB_FAIL;
					goto err;
				}

			}
			else
			{
				ulRet = EErr_SMB_FAIL;
				goto err;
			}

			return 0;
		}

		if(hCon)
		{
			func_CloseContainer(hCon);hCon=NULL;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if(hCon)
	{
		func_CloseContainer(hCon);hCon=NULL;
	}

	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}

COMMON_API unsigned int SMB_DEV_SM2SignDigestProcessV2(SMB_CS_CertificateAttr * pCertAttr, BYTE *pbData, unsigned int ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	OPST_HANDLE_ARGS args = {0};
	OPST_HANDLE_ARGS argsZERO = {0};
	unsigned int ulRet = 0;

	ulRet = SMB_DEV_ArgsGet(pCertAttr,&args);
	if (0 != ulRet)
	{
		goto err;
	}

	if(0 == memcmp(&args, &argsZERO, sizeof(OPST_HANDLE_ARGS)))
	{
		ulRet = SMB_DEV_SM2SignInitializeV2(pCertAttr,&args);

		SMB_DEV_ArgsPut(pCertAttr,&args);

		if (0 != ulRet)
		{
			goto err;
		}
	}


	ulRet = SMB_DEV_SM2SignDigestProcess(&args,pbData,ulDataLen,pSignature);
	if (SAR_FAIL == ulRet)
	{
		SMB_DEV_SM2SignFinalizeV2(&args);
		memcpy(&args,&argsZERO,sizeof(OPST_HANDLE_ARGS));
		ulRet = SMB_DEV_SM2SignInitializeV2(pCertAttr,&args);

		SMB_DEV_ArgsPut(pCertAttr,&args);

		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = SMB_DEV_SM2SignDigestProcess(&args,pbData,ulDataLen,pSignature);

		if (0 != ulRet)
		{
			goto err;
		}
	} 

err:
	if (ulRet)
	{
		SMB_DEV_SM2SignFinalizeV2(&args);
		SMB_DEV_ArgsClr();
	}

	return ulRet;
}

COMMON_API unsigned int SMB_DEV_SM2SignFinalizeV2(OPST_HANDLE_ARGS *args)
{
	unsigned int ulRet = 0;

	ulRet = SMB_DEV_SM2SignFinalize(args);
	if (0 != ulRet)
	{
		goto err;
	}
err:

	return ulRet;
}


COMMON_API unsigned int SMB_DEV_SM2SignDigestForHengBao(SMB_CS_CertificateAttr * pCertAttr,unsigned int ulPINType , CallBackCfcaGetEncryptPIN GetEncryptPIN, void * pArgs/*NULL is able*/, unsigned int *puiRetryCount, BYTE *pbData, unsigned int ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	unsigned int ulRet = 0;
	OPST_HANDLE_ARGS args = {0};
	int isInitArgs = 0;

	ulRet = SMB_DEV_SM2SignInitializeVerifyPINByCertProperty(pCertAttr,ulPINType,GetEncryptPIN,&args,puiRetryCount);
	if (0 != ulRet)
	{
		goto err;
	}

	isInitArgs = 1;

	ulRet = SMB_DEV_SM2SignDigestProcess(&args,pbData,ulDataLen,pSignature);
	if (0 != ulRet)
	{
		goto err;
	}
err:
	if (isInitArgs)
	{
		SMB_DEV_SM2SignFinalize(&args);
	}

	return ulRet;
}


unsigned int SMB_DEV_SM2SignDigestProcess(OPST_HANDLE_ARGS *args, BYTE *pbData, unsigned int ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	HINSTANCE ghInst = NULL;
	unsigned int ulRet = 0;

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_DECLARE(func_, GenRandom, );
	FUNC_NAME_DECLARE(func_, Transmit, );


	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	OPST_HANDLE_ARGS * handleArgs = args;

	if (handleArgs)
	{
		ghInst = handleArgs->ghInst;
		hDev = handleArgs->hDev;
		hAPP = handleArgs->hAPP;
		hCon = handleArgs->hCon;
	}
	else
	{
		return EErr_SMB_FAIL;
	}

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	FUNC_NAME_INIT(func_, ECCSignData,);

	FUNC_NAME_INIT(func_, GenRandom, );
	FUNC_NAME_INIT(func_, Transmit, );

	{
		if(hCon)
		{
			ulRet = func_ECCSignData(hCon,pbData,ulDataLen,pSignature);
			if (0 != ulRet)
			{
				goto err;
			}
		}
		else
		{
			ulRet = EErr_SMB_FAIL;
		}
	}

err:

	return ulRet;
}


unsigned int SMB_DEV_SM2SignInitializeVerifyPINByCertProperty(SMB_CS_CertificateAttr * pCertAttr,unsigned int ulPINType , CallBackCfcaGetEncryptPIN GetEncryptPIN, OPST_HANDLE_ARGS * args, unsigned int *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_DECLARE(func_, GenRandom, );
	FUNC_NAME_DECLARE(func_, Transmit, );
	

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	FUNC_NAME_INIT(func_, ECCSignData,);

	FUNC_NAME_INIT(func_, GenRandom, );
	FUNC_NAME_INIT(func_, Transmit, );

	{
		unsigned char bufferRandom[8] = {0};
		ULONG bufferRandomLen = 8;

		unsigned char szEncrypPin[BUFFER_LEN_1K] = {0};
		unsigned int uiEncryptPinLen = BUFFER_LEN_1K;


		ulRet = func_ConnectDev(pCertAttr->stDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		// 读取KEY的硬件信息
		if (0)
		{
			unsigned char szCommand[BUFFER_LEN_1K];

			unsigned char szOutput[BUFFER_LEN_1K];

			ULONG ulOutputLen = BUFFER_LEN_1K;

			ULONG ulCommandLen = BUFFER_LEN_1K;

			memcpy(szCommand, "\x80\x32\x00\x00\x31",sizeof(szCommand));

			ulCommandLen = 5;

			ulRet = func_Transmit(hDev, szCommand,ulCommandLen,szOutput, &ulOutputLen);

			FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
		}

		ulRet = func_GenRandom(hDev,bufferRandom, 8);
		if (0 != ulRet)
		{
			goto err;
		}

		{
			char szTmpBuffer[BUFFER_LEN_1K] = {0};
			int iTmpBufferLen = BUFFER_LEN_1K;


			iTmpBufferLen = modp_b64_encode_len(sizeof(bufferRandom));
			iTmpBufferLen = modp_b64_encode((char *)szTmpBuffer, (const char*)bufferRandom, 8);

			ulRet = GetEncryptPIN(args, (unsigned char *)szTmpBuffer,iTmpBufferLen,szEncrypPin,&uiEncryptPinLen);
			FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
			if (0 != ulRet)
			{
				goto err;
			}

			FILE_LOG_STRING(file_log_name, (char *)szEncrypPin);
			FILE_LOG_HEX(file_log_name, szEncrypPin, uiEncryptPinLen);

			iTmpBufferLen = modp_b64_decode_len(uiEncryptPinLen);
			iTmpBufferLen = modp_b64_decode(szTmpBuffer, (const char*)szEncrypPin, uiEncryptPinLen);

			FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, iTmpBufferLen);

			memset(szEncrypPin, 0, sizeof(szEncrypPin));
			uiEncryptPinLen=iTmpBufferLen;

			memcpy( szEncrypPin,szTmpBuffer, uiEncryptPinLen);
			FILE_LOG_STRING(file_log_name, (char *)szEncrypPin);
			FILE_LOG_HEX(file_log_name, szEncrypPin, uiEncryptPinLen);
		}

		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
		ulRet = func_OpenApplication(hDev,pCertAttr->stApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);

		ulRet = func_VerifyPIN(hAPP,ulPINType , szEncrypPin, puiRetryCount);
		FILE_LOG_FMT(file_log_name,"func_VerifyPIN");
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, pCertAttr->stContainerName, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}
		else
		{
			OPST_HANDLE_ARGS * handleArgs = args;

			if (handleArgs)
			{
				handleArgs->ghInst = ghInst;
				handleArgs->hDev = hDev;
				handleArgs->hAPP = hAPP;
				handleArgs->hCon = hCon;

				if(hCon)
				{
					/*unsigned char digest[32] = {0};

					unsigned int ulRetry = 0;

					ECCSIGNATUREBLOB blob;

					ulRet = func_ECCSignData(hCon,digest,sizeof(digest),&blob);
					ulRet = func_VerifyPIN(hAPP,ulPINType , szEncrypPin, puiRetryCount);
					if (0 != ulRet)
					{
					goto err;
					}

					ulRet = func_ECCSignData(hCon,digest,sizeof(digest),&blob);


					if (0 != ulRet)
					{
					goto err;
					}*/
				}
				else
				{
					ulRet = EErr_SMB_FAIL;
					goto err;
				}

			}
			else
			{
				ulRet = EErr_SMB_FAIL;
				goto err;
			}

			return 0;
		}

		if(hCon)
		{
			func_CloseContainer(hCon);hCon=NULL;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if(hCon)
	{
		func_CloseContainer(hCon);hCon=NULL;
	}

	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_SM2SignFinalize(OPST_HANDLE_ARGS * args)
{
	HINSTANCE ghInst = NULL;
	unsigned int ulRet = 0;

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_DECLARE(func_, GenRandom, );
	FUNC_NAME_DECLARE(func_, Transmit, );


	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	OPST_HANDLE_ARGS * handleArgs = args;


	if (handleArgs)
	{
		ghInst = handleArgs->ghInst;
		hDev = handleArgs->hDev;
		hAPP = handleArgs->hAPP;
		hCon = handleArgs->hCon;
	}
	else
	{
		return EErr_SMB_FAIL;
	}

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	FUNC_NAME_INIT(func_, GenRandom, );
	FUNC_NAME_INIT(func_, Transmit, );

err:

	if(hCon)
	{
		func_CloseContainer(hCon);hCon=NULL;
	}

	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}

#endif



unsigned int SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	unsigned int ulRet = 0;

	unsigned int sigLen = SM2_BYTES_LEN * 2;
	unsigned char sigValue[SM2_BYTES_LEN * 2] = {0}; 

	memcpy(sigValue, pSignature->r + SM2_BYTES_LEN, SM2_BYTES_LEN);
	memcpy(sigValue + SM2_BYTES_LEN, pSignature->s + SM2_BYTES_LEN, SM2_BYTES_LEN);

	ulRet = OpenSSL_Initialize();
	if (ulRet)
	{
		ulRet = -1;
		goto err;
	}

	ulRet = OpenSSL_SM2VerifyDigest(pbData, ulDataLen,
		sigValue,sigLen,
		pECCPubKeyBlob->XCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN,
		pECCPubKeyBlob->YCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN);

	if (ulRet)
	{
		// error;
	}
err:

	OpenSSL_Finalize();

	return ulRet;
}

unsigned int SMB_DEV_EnumCertInternal(const char * pszSKFName, void * pvCertsValue,unsigned int *puiCertsLen, unsigned int ulKeyFlag, unsigned int ulSignFlag,unsigned int ulVerifyFlag, unsigned int ulFilterFlag)
{
	unsigned int ulRet = 0;

	char * data_value = NULL;
	unsigned int ulOutLen = 0;
	char * ptr_SKF = NULL;
	char szSKFAll[BUFFER_LEN_1K] = {0};
	unsigned int ulSKFAll = 1024;

	SMB_CS_CertificateContext * pCertCtx = NULL;

	data_value = (char *)malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);

	pCertCtx = (SMB_CS_CertificateContext * )data_value;

	if (NULL == pszSKFName)
	{
		char * ptr_data_value = data_value;
		unsigned int data_len_tmp = BUFFER_LEN_1K * BUFFER_LEN_1K;

		ulOutLen = 0;
		
		SMB_DEV_EnumSKF(szSKFAll, &ulSKFAll);
		
		for(ptr_SKF = szSKFAll; (ptr_SKF < szSKFAll + ulSKFAll) && *ptr_SKF != 0;)
		{
			data_len_tmp = BUFFER_LEN_1K * BUFFER_LEN_1K;
			
			ulRet = SMB_DEV_EnumCertBySKF(ptr_SKF, ptr_data_value, &data_len_tmp,ulKeyFlag,ulSignFlag,ulVerifyFlag,ulFilterFlag);

			
			// next SKF
			ptr_SKF += strlen(ptr_SKF) + 1;

			if (ulRet)
			{
				continue;
			}
			else
			{
				ptr_data_value += data_len_tmp;
				ulOutLen += data_len_tmp;
			}
		}
	}
	else
	{
		ulOutLen = BUFFER_LEN_1K * BUFFER_LEN_1K;

		ulRet = SMB_DEV_EnumCertBySKF(pszSKFName, data_value, &ulOutLen,ulKeyFlag,ulSignFlag,ulVerifyFlag,ulFilterFlag);

		if (ulRet)
		{
			goto err;
		}
	}

	ulRet = -1;

	if (NULL == pvCertsValue)
	{
		* puiCertsLen = ulOutLen;

		ulRet = 0;

		goto err;
	}
	else if (* puiCertsLen < ulOutLen)
	{
		* puiCertsLen = ulOutLen;

		ulRet = EErr_SMB_MEM_LES;

		goto err;
	}
	else
	{
		memcpy(pvCertsValue,data_value,ulOutLen);

		for (pCertCtx = (SMB_CS_CertificateContext *)pvCertsValue;(char *)pCertCtx < (char *)pvCertsValue + ulOutLen;)
		{
			pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext) ;

			SMB_DEV_CertGetProperty(pCertCtx->pbValue,pCertCtx->nValueLen,&(pCertCtx->stProperty));

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext) ;
		}

		* puiCertsLen = ulOutLen;
		ulRet = 0;
	}

err:
	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}

unsigned int SMB_DEV_VerifyCert(unsigned int ulFlag,unsigned int ulAlgType, BYTE* pbCert, unsigned int ulCertLen)
{
	unsigned int ulRet = 0;

	unsigned int ulOutLen = 0;

	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = {0};
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;


	switch(ulAlgType)
	{
	case CERT_ALG_RSA_FLAG:
		{
			// 创建上下文
			certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
			if (!certContext_IN)
			{
				ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
				goto err;
			}
			// TIME
			if(CERT_VERIFY_TIME_FLAG & ulFlag)
			{
				ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
				if(ulRet)
				{
					ulRet = EErr_SMB_VERIFY_TIME;
					goto err;
				}
			}
			// SIGN CERT
			if (CERT_VERIFY_CHAIN_FLAG & ulFlag)
			{
				// 打开存储区		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
					// not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
					// registry location
					L"Ca"                            // The store name as a Unicode 
					// string
					);

				if (NULL == hCertStore)
				{
					ulRet = EErr_SMB_OPEN_STORE;
					goto err;
				}

				// 查找颁发者证书
				certContext_OUT = CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,0,CERT_FIND_ISSUER_OF,certContext_IN,NULL);

				if (NULL == certContext_OUT)
				{
					if (hCertStore)
					{
						// 关闭存储区
						CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
					}

					// 打开存储区		
					hCertStore = CertOpenStore(
						CERT_STORE_PROV_SYSTEM,          // The store provider type
						0,                               // The encoding type is
						// not needed
						NULL,                            // Use the default HCRYPTPROV
						CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
						// registry location
						L"Root"                            // The store name as a Unicode 
						// string
						);

					if (NULL == hCertStore)
					{
						ulRet = EErr_SMB_OPEN_STORE;
						goto err;
					}

					// 查找颁发者证书
					certContext_OUT = CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,0,CERT_FIND_ISSUER_OF,certContext_IN,NULL);
				}

				if (NULL != certContext_OUT)
				{
					DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG;

					// 验证颁发者证书
					if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, ulCertLen))
					{
						// 验证根证书
						//ulRet = SMB_DEV_VerifyRootCert(ulFlag,ulAlgType, certContext_OUT->pbCertEncoded,certContext_OUT->cbCertEncoded);
					}
					else
					{
						// 验证上级证书
						ulRet = SMB_DEV_VerifyCert(ulFlag,ulAlgType, certContext_OUT->pbCertEncoded,certContext_OUT->cbCertEncoded);
						if (ulRet)
						{
							goto err;
						}

					}

					ulRet = CertVerifySubjectCertificateContext(certContext_IN, certContext_OUT,&dwFlags);
					if(TRUE != ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}

					if (dwFlags)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
					}
				}
				else
				{
					ulRet = EErr_SMB_NO_CERT_CHAIN;
					goto err;
				}
			}
			//CRL
			if (CERT_VERIFY_CRL_FLAG & ulFlag)
			{

			}
		}
		break;
	case CERT_ALG_SM2_FLAG:
		{
			// 创建上下文
			certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
			if (!certContext_IN)
			{
				ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
				goto err;
			}
			// TIME
			if(CERT_VERIFY_TIME_FLAG & ulFlag)
			{
				ulRet = SMC_CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
				if(ulRet)
				{
					ulRet = EErr_SMB_VERIFY_TIME;
					goto err;
				}
			}
			// SIGN CERT
			if (CERT_VERIFY_CHAIN_FLAG & ulFlag)
			{
				// 创建存储区
				ulRet = SMC_CertCreateSMCStores();

				if(TRUE != ulRet)
				{
					ulRet = EErr_SMB_CREATE_STORE;
					goto err;
				}

				// 打开存储区	

				hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_ROOT_ID);

				if (NULL == hCertStore)
				{
					ulRet = EErr_SMB_OPEN_STORE;
					goto err;
				}

				// 查找颁发者证书
				certContext_OUT = SMC_CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,CERT_FIND_ISSUER_OF,certContext_IN,NULL);

				if (NULL != certContext_OUT)
				{
					// 验证颁发者证书
					if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, ulCertLen))
					{
						// 验证
						// ulRet = SMB_DEV_VerifyRootCert(ulFlag,ulAlgType, certContext_OUT->pbCertEncoded,certContext_OUT->cbCertEncoded);
					}
					else
					{
						// 验证上级证书
						ulRet = SMB_DEV_VerifyCert(ulFlag,ulAlgType, certContext_OUT->pbCertEncoded,certContext_OUT->cbCertEncoded);

						if (ulRet)
						{
							goto err;
						}
					}

					// 导出公钥
					ulRet = SMC_CertExportPublicKeyInfo(certContext_OUT, NULL, &ulOutLen);

					if(TRUE != ulRet)
					{
						ulRet = EErr_SMB_EXPORT_PUK;
						goto err;
					}

					ulRet = SMC_CertExportPublicKeyInfo(certContext_OUT, &certPublicKeyInfo, &ulOutLen);
					if(TRUE != ulRet)
					{
						ulRet = EErr_SMB_EXPORT_PUK;
						goto err;
					}

					ulRet = SMC_CertVerifyCertificateSignature(pbCert, ulCertLen, &certPublicKeyInfo);
					if(TRUE != ulRet)
					{
						ulRet = EErr_SMB_VERIFY_CERT;
						goto err;
					}
					else
					{
						ulRet = 0;
					}
				}
				else
				{
					ulRet = EErr_SMB_NO_CERT_CHAIN;
					goto err;
				}
			}
			//CRL
			if (CERT_VERIFY_CRL_FLAG & ulFlag)
			{

			}
		}
		break;
	default:
		break;
	}

err:
	// 释放上下文
	if(certContext_OUT)
	{
		SMC_CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if(certContext_IN)
	{
		SMC_CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}

unsigned int SMB_DEV_VerifyRootCert(unsigned int ulFlag,unsigned int ulAlgType, BYTE* pbCert, unsigned int ulCertLen)
{
	unsigned int ulRet = 0;
	unsigned int ulOutLen = 0;
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = {0};
	PCCERT_CONTEXT certContext_IN = NULL;

	switch(ulAlgType)
	{
	case CERT_ALG_RSA_FLAG:
		{
			// 创建上下文
			certContext_IN = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
			if (!certContext_IN)
			{
				ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
				goto err;
			}
			// TIME
			if(CERT_VERIFY_TIME_FLAG&ulFlag)
			{
				ulRet = CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
				if(ulRet)
				{
					ulRet = EErr_SMB_VERIFY_TIME;
					goto err;
				}
			}
			// SIGN CERT
			if (CERT_VERIFY_CHAIN_FLAG&ulFlag)
			{

				DWORD  dwFlags = CERT_STORE_SIGNATURE_FLAG ;


				ulRet = CertVerifySubjectCertificateContext(certContext_IN, certContext_IN,&dwFlags);
				if(TRUE != ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}
			}
			//CRL
			if (CERT_VERIFY_CRL_FLAG&ulFlag)
			{

			}
		}
		break;

	case CERT_ALG_SM2_FLAG:
		{
			// 创建上下文
			certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
			if (!certContext_IN)
			{
				ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
				goto err;
			}
			// TIME
			if(CERT_VERIFY_TIME_FLAG&ulFlag)
			{
				ulRet = SMC_CertVerifyTimeValidity(NULL, certContext_IN->pCertInfo);
				if(ulRet)
				{
					ulRet = EErr_SMB_VERIFY_TIME;
					goto err;
				}
			}
			// SIGN CERT
			if (CERT_VERIFY_CHAIN_FLAG&ulFlag)
			{
				// 导出公钥
				ulRet = SMC_CertExportPublicKeyInfo(certContext_IN, NULL, &ulOutLen);

				if(TRUE != ulRet)
				{
					ulRet = EErr_SMB_EXPORT_PUK;
					goto err;
				}

				ulRet = SMC_CertExportPublicKeyInfo(certContext_IN, &certPublicKeyInfo, &ulOutLen);
				if(TRUE != ulRet)
				{
					ulRet = EErr_SMB_EXPORT_PUK;
					goto err;
				}

				ulRet = SMC_CertVerifyCertificateSignature(pbCert, ulCertLen, &certPublicKeyInfo);
				if(TRUE != ulRet)
				{
					ulRet = EErr_SMB_VERIFY_CERT;
					goto err;
				}
				else
				{
					ulRet = 0;
				}

			}
			//CRL
			if (CERT_VERIFY_CRL_FLAG&ulFlag)
			{

			}
		}
		break;
	default:
		break;
	}

err:

	if(certContext_IN)
	{
		SMC_CertFreeCertificateContext(certContext_IN);
	}

	return ulRet;
}

void TimetToSystemTime( time_t t, LPSYSTEMTIME pst);
void SystemTimeToTime_t( SYSTEMTIME st, time_t *pt);
void  FileTimeToTime_t(  FILETIME  ft,  time_t  *t);

unsigned int SMB_DEV_CertGetProperty(BYTE* pbCert, unsigned int ulCertLen, SMB_CS_CertificateAttr * pCertAttr)
{
	unsigned int ulRet = 0;
	if (NULL == pCertAttr || NULL == pbCert || 0 == ulCertLen)
	{
		return 0;
	}
	else
	{
		//2.获取CertContext
		PCCERT_CONTEXT pCertContext = NULL;
		CRYPT_INTEGER_BLOB snBlob;
		CERT_NAME_BLOB issuerBlob;
		CERT_NAME_BLOB subjectBlob;
		SYSTEMTIME sysTime;
		char szTime[128] = {0};

		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, ulCertLen);

		if (NULL == pCertContext)
		{
			ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
			goto err;
		}

		//3.获取证书信息
		pCertContext->pCertInfo->dwVersion; // 证书版本
		snBlob = pCertContext->pCertInfo->SerialNumber; // 证书SN
		issuerBlob = pCertContext->pCertInfo->Issuer; // 证书颁发者
		subjectBlob = pCertContext->pCertInfo->Subject; // 证书主题

		// 证书有效起始日期
		memset(&sysTime, 0, sizeof(sysTime));
		FileTimeToSystemTime(&pCertContext->pCertInfo->NotBefore, &sysTime);
		SystemTimeToTime_t( sysTime,&(pCertAttr->ulNotBefore));
		memset(szTime, 0, sizeof(szTime));
		sprintf_s(szTime, 128, "%04d-%02d-%02d %02d:%02d:%02d", sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		// 证书有效终止日期
		memset(&sysTime, 0, sizeof(sysTime));
		FileTimeToSystemTime(&pCertContext->pCertInfo->NotAfter, &sysTime);
		SystemTimeToTime_t( sysTime,&(pCertAttr->ulNotAfter));
		memset(szTime, 0, sizeof(szTime));
		sprintf_s(szTime, 128, "%04d-%02d-%02d %02d:%02d:%02d", sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);

		CertGetNameStringA(pCertContext,CERT_NAME_ATTR_TYPE,0,NULL, pCertAttr->stCommonName, 64);

		CertFreeCertificateContext(pCertContext);
	}

err:

	return ulRet;

}

#include "Cryptuiapi.h"

unsigned int SMB_DEV_UIDlgViewContext(BYTE* pbCert, unsigned int ulCertLen)
{
	//2.获取CertContext
	PCCERT_CONTEXT pCertContext = NULL;
	unsigned int ulRet = 0;

	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, ulCertLen);

	if (NULL == pCertContext)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT,pCertContext,GetForegroundWindow(),NULL,0,NULL);

err:
	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}

	return ulRet;
}


COMMON_API unsigned int SMB_DEV_ImportCaCert(BYTE * pbCert, unsigned int ulCertLen, unsigned int * pulAlgType)
{
	unsigned int ulRet = 0;
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore = NULL;

	unsigned char pbAlg[64];
	unsigned long ulAlgLen = 64;

	unsigned long bRootCert = 0; // 是否是根CA
	unsigned long bSM2cert = 0; // 是否是SM2证书

	// 存储区证书
	SMB_CS_CertificateAttr * descProperty_IN = NULL;

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	ulRet = OpenSSL_CertSubjectCompareIssuer(pbCert, ulCertLen, &bRootCert);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	if (ulRet)
	{
		ulRet = EErr_SMB_INVALIDARG;
		goto err;
	}

	ulRet = OpenSSL_CertGetPublicKeyAlgor(pbCert, ulCertLen,pbAlg,&ulAlgLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	if (ulRet)
	{
		ulRet = EErr_SMB_INVALIDARG;
		goto err;
	}

	if (0 == memcmp(pbAlg,SM2_ALG_BYTES,ulAlgLen))
	{
		bSM2cert = 1;
		* pulAlgType  = CERT_ALG_SM2_FLAG;
	}
	else
	{
		bSM2cert = 0;
		* pulAlgType  = CERT_ALG_RSA_FLAG;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	descProperty_IN = (SMB_CS_CertificateAttr * )malloc(sizeof(SMB_CS_CertificateAttr));

	ulRet = SMC_CertCreateSMCStores();
	if (!ulRet)
	{
		ulRet = EErr_SMB_CREATE_STORE;
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	if (bSM2cert)
	{
		// 打开SM2根存储区
		hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_ROOT_ID);
	}
	else
	{
		if (bRootCert)
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
				// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
				// registry location
				L"Root"                            // The store name as a Unicode 
				// string
				);
		}
		else
		{
			// 打开存储区	
			hCertStore = CertOpenStore(
				CERT_STORE_PROV_SYSTEM,          // The store provider type
				0,                               // The encoding type is
				// not needed
				NULL,                            // Use the default HCRYPTPROV
				CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
				// registry location
				L"Ca"                            // The store name as a Unicode 
				// string
				);
		}

	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "hCertStore");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, hCertStore);

	if (NULL == hCertStore)
	{
		SMB_DEV_PrintErrorMsg();
		ulRet = EErr_SMB_OPEN_STORE;
		goto err;
	}

	// 置空属性
	memset(descProperty_IN, 0,sizeof(SMB_CS_CertificateAttr));

	// 创建上下文
	certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert,ulCertLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "certContext_IN");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, certContext_IN);
	if (!certContext_IN)
	{
		SMB_DEV_PrintErrorMsg();
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	// 设置属性
	ulRet = SMC_CertSetCertificateContextProperty(certContext_IN, CERT_DESC_PROP_ID,CERT_STORE_NO_CRYPT_RELEASE_FLAG, descProperty_IN);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	
	if (!ulRet)
	{
		SMB_DEV_PrintErrorMsg();
		ulRet = EErr_SMB_SET_CERT_CONTEXT_PROPERTY;
		goto err;

	}

	// 保存证书
	ulRet = SMC_CertAddCertificateContextToStore(hCertStore,certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	

	if(!ulRet)
	{
		// err message 
		SMB_DEV_PrintErrorMsg();

		if (0x80070005 == GetLastError())
		{
			ulRet = EErr_SMB_NO_RIGHT;
		}
		else
		{
			ulRet = EErr_SMB_ADD_CERT_TO_STORE;
		}


		goto err;
	}
	else
	{
		ulRet = EErr_SMB_OK; // success
	}

err:
	if (descProperty_IN)
	{
		free(descProperty_IN);
	}

	if(certContext_IN)
	{
		// 释放上下文
		SMC_CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}





unsigned int SMB_DEV_IsSM2RootCert(BYTE* pbCert, unsigned int ulCertLen,unsigned int * bIRoot)
{
	unsigned int ulRet = 0;

	unsigned int ulOutLen = 0;

	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = {0};
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;

	* bIRoot = 0; // 不为根证

	certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
	if (!certContext_IN)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	// 打开存储区		
	hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_ROOT_ID);

	if (NULL == hCertStore)
	{
		ulRet = EErr_SMB_OPEN_STORE;
		goto err;
	}

	// 查找颁发者证书
	certContext_OUT = SMC_CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,CERT_FIND_ISSUER_OF,certContext_IN,NULL);

	if (NULL != certContext_OUT)
	{
		// 是否是Root证书
		if (0 == memcmp(certContext_OUT->pbCertEncoded, pbCert, ulCertLen))
		{
			* bIRoot = 1;// 为根证
		}
		else
		{
			* bIRoot = 0;// 不为根证
		}
	}
	else
	{
		ulRet = EErr_SMB_NO_CERT_CHAIN;
		goto err;
	}

err:
	// 释放上下文
	if(certContext_OUT)
	{
		SMC_CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if(certContext_IN)
	{
		SMC_CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}
unsigned int SMB_DEV_FindSM2CACert(BYTE* pbCert, unsigned int ulCertLen,
	BYTE* pbCACert, unsigned int * ulCACertLen
	)
{
	unsigned int ulRet = 0;

	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = {0};
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_OUT = NULL;
	PCCERT_CONTEXT certContext_IN = NULL;

	certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, pbCert,ulCertLen);
	if (!certContext_IN)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	// 打开存储区		
	hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_ROOT_ID);

	if (NULL == hCertStore)
	{
		ulRet = EErr_SMB_OPEN_STORE;
		goto err;
	}

	// 查找颁发者证书
	certContext_OUT = SMC_CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,CERT_FIND_ISSUER_OF,certContext_IN,NULL);



	if (NULL != certContext_OUT)
	{
		if ( pbCACert == NULL)
		{
			* ulCACertLen = certContext_OUT->cbCertEncoded;
		}
		else if (* ulCACertLen < certContext_OUT->cbCertEncoded)
		{
			* ulCACertLen = certContext_OUT->cbCertEncoded;
			ulRet = EErr_SMB_MEM_LES;
		}
		else
		{
			* ulCACertLen = certContext_OUT->cbCertEncoded;
			memcpy(pbCACert,  certContext_OUT->pbCertEncoded, * ulCACertLen);
		}
	}
	else
	{
		ulRet = EErr_SMB_NO_CERT_CHAIN;
		goto err;
	}

err:
	// 释放上下文
	if(certContext_OUT)
	{
		SMC_CertFreeCertificateContext(certContext_OUT);
	}

	// 释放上下文
	if(certContext_IN)
	{
		SMC_CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 关闭存储区
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}

unsigned int SMB_DEV_FindEnCertificateByCertDescProperty(
	_In_ SMB_CS_CertificateAttr * pCertAttr, _Out_ unsigned char * pbCert, _Inout_ unsigned int * pulCertLen
	)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = -1;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, ECCSignData,);
	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	{


		ulRet = func_ConnectDev(pCertAttr->stDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev,pCertAttr->stApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, pCertAttr->stContainerName, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_ExportCertificate(hCon,FALSE, pbCert, (ULONG *)pulCertLen);

		ulRet = func_CloseContainer(hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}



err:
	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	return ulRet;
}



COMMON_API unsigned int SMB_DEV_SM2GetAgreementKey(
	_In_ SMB_CS_CertificateAttr * pCertAttr,
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
	_Inout_ ULONG * puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev,);
	FUNC_NAME_DECLARE(func_, ConnectDev,);
	FUNC_NAME_DECLARE(func_, DisConnectDev,);
	FUNC_NAME_DECLARE(func_, ChangePIN,);
	FUNC_NAME_DECLARE(func_, OpenApplication,);
	FUNC_NAME_DECLARE(func_, CloseApplication,);
	FUNC_NAME_DECLARE(func_, EnumApplication,);
	FUNC_NAME_DECLARE(func_, ExportCertificate,);
	FUNC_NAME_DECLARE(func_, EnumContainer,);
	FUNC_NAME_DECLARE(func_, OpenContainer,);
	FUNC_NAME_DECLARE(func_, CloseContainer,);
	FUNC_NAME_DECLARE(func_, VerifyPIN,);
	FUNC_NAME_DECLARE(func_, GetContainerType,);
	FUNC_NAME_DECLARE(func_, ECCSignData,);
	FUNC_NAME_DECLARE(func_, ECCVerify,);
	FUNC_NAME_DECLARE(func_, ExtECCVerify,);
	FUNC_NAME_DECLARE(func_, GetDevInfo,);
	FUNC_NAME_DECLARE(func_, LockDev,);
	FUNC_NAME_DECLARE(func_, UnlockDev,);

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;


	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = {0};

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;
	HANDLE hAgreementHandle = NULL;

	ulRet = SMB_CS_ReadSKFPath(pCertAttr->stSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev,);
	FUNC_NAME_INIT(func_, ConnectDev,);
	FUNC_NAME_INIT(func_, DisConnectDev,);
	FUNC_NAME_INIT(func_, ChangePIN,);
	FUNC_NAME_INIT(func_, OpenApplication,);
	FUNC_NAME_INIT(func_, CloseApplication,);
	FUNC_NAME_INIT(func_, EnumApplication,);
	FUNC_NAME_INIT(func_, ExportCertificate,);
	FUNC_NAME_INIT(func_, EnumContainer,);
	FUNC_NAME_INIT(func_, OpenContainer,);
	FUNC_NAME_INIT(func_, CloseContainer,);
	FUNC_NAME_INIT(func_, VerifyPIN,);
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType,);
	FUNC_NAME_INIT(func_, ECCSignData,);

	FUNC_NAME_INIT(func_, GenerateKeyWithECCEx,);
	FUNC_NAME_INIT(func_, GenerateAgreementDataWithECC,);
	FUNC_NAME_INIT(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_INIT(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_INIT(func_, LockDev,);
	FUNC_NAME_INIT(func_, UnlockDev,);

	{
		ulRet = func_ConnectDev(pCertAttr->stDeviceName, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if(ulRet=SDSCWaitMutex(mutex_buffer,INFINITE,&hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev,0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev,pCertAttr->stApplicationName,&hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, pCertAttr->stContainerName, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}

#if  0
		//send
		ulRet = func_GenerateAgreementDataWithECCEx(hCon,ulAlgId,pTempECCPubKeyBlobA,pbIDA,ulIDALen,&hAgreementHandle);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_GenerateKeyWithECCEx(hAgreementHandle, pECCPubKeyBlobB,pTempECCPubKeyBlobB,pbIDB,ulIDBLen,pbAgreementKey,pulAgreementKeyLen);
		if (0 != ulRet)
		{
			goto err;
		}
#else
		//re
		ulRet = func_GenerateAgreementDataAndKeyWithECCEx(hCon, ulAlgId, pECCPubKeyBlobB, pTempECCPubKeyBlobB, pTempECCPubKeyBlobA, pbIDB, ulIDBLen, pbIDA, ulIDALen, pbAgreementKey, pulAgreementKeyLen);
		if (0 != ulRet)
		{
			goto err;
		}
#endif
		ulRet = func_CloseContainer(hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev);hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if(hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev);hDev = NULL;
	}

	if(ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}

COMMON_API unsigned int SMB_DEV_SM2GetAgreementKeyEx(
	_In_ BYTE* pbCert, 
	_In_ unsigned int ulCertLen,
	_In_ int ulAlgId,
	_Out_ BYTE* pbTempECCPubKeyBlobA,
	_Inout_ int *pulTempECCPubKeyBlobALen,
	_In_ BYTE* pbIDA,
	_In_ int ulIDALen,
	_In_ BYTE* pbECCPubKeyBlobB,
	_In_ int  ulECCPubKeyBlobBLen,
	_In_ BYTE* pbTempECCPubKeyBlobB,
	_In_ int  ulTempECCPubKeyBlobBLen,
	_In_ BYTE* pbIDB,
	_In_ int ulIDBLen,
	_Out_ BYTE *pbAgreementKey,
	_Inout_ int *pulAgreementKeyLen,
	_In_ const char * pszPIN,
	_Inout_ int * puiRetryCount)
{
	SMB_CS_CertificateAttr  pCertAttr = { 0 };

	ECCPUBLICKEYBLOB  pTempECCPubKeyBlobA = { 0 };
	ECCPUBLICKEYBLOB  pECCPubKeyBlobB = { 0 };
	ECCPUBLICKEYBLOB  pTempECCPubKeyBlobB = { 0 };
	ECCPUBLICKEYBLOB  pTemp = { 0 };

	unsigned int		uiRet = 0;

	unsigned int		uiECCBitLen = 256;
	unsigned int		uiECCLen = uiECCBitLen/8;

	uiRet = SMC_CertGetCertificateContextPropertyByCert(pbCert, ulCertLen, &pCertAttr);
	if (0 != uiRet)
	{
		return uiRet;
	}
	pCertAttr.ucCertUsageType = 2;

	//04 + X + Y
	pECCPubKeyBlobB.BitLen = uiECCBitLen;
	memcpy(pECCPubKeyBlobB.XCoordinate + 64 - uiECCLen, pbECCPubKeyBlobB + 1, uiECCLen);
	memcpy(pECCPubKeyBlobB.YCoordinate + 64 - uiECCLen, pbECCPubKeyBlobB + 1 + uiECCLen, uiECCLen);

	pTempECCPubKeyBlobB.BitLen = uiECCBitLen;
	memcpy(pTempECCPubKeyBlobB.XCoordinate + 64 - uiECCLen, pbTempECCPubKeyBlobB + 1, uiECCLen);
	memcpy(pTempECCPubKeyBlobB.YCoordinate + 64 - uiECCLen, pbTempECCPubKeyBlobB + 1 + uiECCLen, uiECCLen);

	uiRet = SMB_DEV_SM2GetAgreementKey(&pCertAttr, ulAlgId, &pTempECCPubKeyBlobA, pbIDA, ulIDALen,
		&pECCPubKeyBlobB, &pTempECCPubKeyBlobB, pbIDB, ulIDBLen, 
		pbAgreementKey, pulAgreementKeyLen, pszPIN, puiRetryCount);
	if (0 != uiRet)
	{
		return uiRet;
	}

	if (NULL == pbTempECCPubKeyBlobA)
	{
		*pulTempECCPubKeyBlobALen = 0x41;
		return uiRet;
	}

	if ((*pulTempECCPubKeyBlobALen) < 0x41)
	{
		*pulTempECCPubKeyBlobALen = 0x41;
		return EErr_SMB_MEM_LES;
	}

	*pulTempECCPubKeyBlobALen = 0x41;
	memcpy(pbTempECCPubKeyBlobA, "\x04", 1);
	memcpy(pbTempECCPubKeyBlobA + 1, pTempECCPubKeyBlobA.XCoordinate + 64 - uiECCLen, uiECCLen);
	memcpy(pbTempECCPubKeyBlobA + 1 + uiECCLen, pTempECCPubKeyBlobA.YCoordinate + 64 - uiECCLen, uiECCLen);

	return uiRet;
}

#endif