#ifndef __WTF_INTERFACE_H__

#define __WTF_INTERFACE_H__

#include <windows.h>
#include "smb_cs.h"
#include "SKFInterface.h"


// ֤��(��Կ���ͱ�־) ��������λ�����
typedef enum _WTF_CERT_ALG_FLAG
{
	CERT_ALG_RSA_FLAG = 0x00000001,		// RSA֤��
	CERT_ALG_SM2_FLAG = 0x00000002,		// SM2֤��

}WTF_CERT_ALG_TYPE;

// ֤��(ǩ��|���ܱ�־) ��������λ�����
typedef enum _WTF_CERT_USAGE_FLAG
{
	CERT_SIGN_FLAG = 0x00000001,		// ǩ��֤��
	CERT_EX_FLAG = 0x00000002,		// ����֤��

}WTF_CERT_USAGE_FLAG;

// ֤��(��֤��־) ��������λ�����
typedef enum _WTF_CERT_VERIFY_FLAG
{
	CERT_NOT_VERIFY_FLAG = 0x00000000,		// ����֤
	CERT_VERIFY_TIME_FLAG = 0x00000001,		// ʹ�ñ��ص�ǰʱ����֤��Ч��
	CERT_VERIFY_CHAIN_FLAG = 0x00000002,		// ��֤֤�����Լ�ǩ��
	CERT_VERIFY_CRL_FLAG = 0x00000004,		// ��δʵ��

}WTF_CERT_VERIFY_FLAG;

// ��֤���
typedef enum _WTF_CERT_VERIFY_RESULT_FLAG
{
	CERT_VERIFY_RESULT_FLAG_OK = 0x00000000,		// ��֤�ɹ�
	CERT_VERIFY_RESULT_TIME_INVALID = 0x00000001,		// ������Ч��
	CERT_VERIFY_RESULT_CHAIN_INVALID = 0x00000002,		// ֤�����쳣
	CERT_VERIFY_RESULT_SIGN_INVALID = 0x00000003,		// �Ƿ��û�֤��
	CERT_VERIFY_RESULT_CRL_INVALID = 0x00000004,		// ��δ����

}WTF_CERT_VERIFY_RESULT_FLAG;


typedef enum _WTF_CERT_FILTER_FLAG
{
	CERT_FILTER_FLAG_FALSE = 0x00000000,		// ������
	CERT_FILTER_FLAG_TRUE = 0x00000001,		// ����
}WTF_CERT_FILTER_FLAG;

// ֤��ṹ��
typedef struct _SK_CERT_CONTENT {
	SK_CERT_DESC_PROPERTY stProperty;				// ����
	unsigned int nValueLen;							// ֤�����ݳ���
	BYTE *pbValue;									// ֤������
}SK_CERT_CONTENT;




#ifdef __cplusplus
extern "C" {
#endif
	/*
	��������:	ö��SKF��
	��������:	WTF_EnumSKF
	�������:
	�������:
	pszSKFNames		 ���ַ���
	puiSKFNamesLen   ���ַ�������
	����ֵ:
	ʧ�ܣ�
	��������:	ö��SKF��
	*/
	COMMON_API unsigned int __stdcall WTF_EnumSKF(char * pszSKFNames, unsigned int *puiSKFNamesLen);
	/*
	��������:	��ȡָ��SKF�����·��
	��������:	WTF_ReadSKFPath
	�������:	pszSKFName SKF��
	�������:
	pszDllPath		SKF�����·��
	puiDllPathLen	����
	����ֵ:
	ʧ�ܣ�
	��������:	��ȡָ��SKF�����·��
	*/
	COMMON_API unsigned int __stdcall WTF_ReadSKFPath(const char * pszSKFName, char * pszDllPath, unsigned int *puiDllPathLen);


	/*
	��������:	��ȡָ��SKFǩ������
	��������:	WTF_ReadSKFSignType
	�������:	pszSKFName SKF��
	�������:
	pszSignType		SKF�����·��
	puiSignTypeLen	����
	����ֵ:
	ʧ�ܣ�
	��������:	��ȡָ��SKFǩ������
	*/
	COMMON_API unsigned int __stdcall WTF_ReadSKFSignType(const char * pszSKFName, char * pszSignType, unsigned int *puiSignTypeLen);

	/*
	��������:	ö��֤��
	��������:	WTF_EnumCertInternal
	�������:
	pszSKFName SKF��(NULL ����ȫ��SKF��)
	uiKeyFlag
	֤��(��Կ���ͱ�־) ��������λ�����
	�μ� WTF_CERT_ALG_FLAG
	uiSignFlag
	֤��(ǩ��|���ܱ�־) ��������λ�����
	�μ� WTF_CERT_SIGN_FLAG

	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� WTF_CERT_VERIFY_FLAG
	�������:
	pvCertsValue	��֤�鴮
	puiCertsLen		����
	����ֵ:
	ʧ�ܣ�
	��������:	ö��֤��
	*/
	COMMON_API unsigned int __stdcall WTF_EnumCertInternal(const char *pszSKFName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);
	COMMON_API unsigned int __stdcall WTF_EnumCertInternalBySKF(const char * pszSKFName, void * pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);
	COMMON_API unsigned int __stdcall WTF_EnumCertInternalByProperty(SK_CERT_DESC_PROPERTY * pCertProperty, void * pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);
	/*
	��������:	ö���豸
	��������:	WTF_EnumDev
	�������:
	�������:
	pszDevsName		���ַ�������ʾ����豸��,��ͬ���豸��֮����0x00�������0x0000��ʾ���ַ�������
	puiDevsNameLen	���ض��ַ�������
	����ֵ:
	ʧ�ܣ�
	��������:	ö���豸
	*/
	COMMON_API unsigned int __stdcall WTF_EnumDev(char *pszDevsName, unsigned int *puiDevsNameLen);

	/*
	��������:	ö��֤��
	��������:	WTF_EnumCert
	�������:
	pszSKFName SKF��(NULL ����ȫ��SKF��)
	uiKeyFlag
	֤��(��Կ���ͱ�־) ��������λ�����
	�μ� WTF_CERT_ALG_FLAG
	uiSignFlag
	֤��(ǩ��|���ܱ�־) ��������λ�����
	�μ� WTF_CERT_SIGN_FLAG

	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� WTF_CERT_VERIFY_FLAG
	�������:
	pvCertsValue	��֤�鴮
	puiCertsLen		����
	����ֵ:
	ʧ�ܣ�
	��������:	ö��֤��
	*/
	COMMON_API unsigned int __stdcall WTF_EnumCert(const char *pszDevName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	��������:	�޸����루ǩ��֤������豸��
	��������:	WTF_ChangePIN
	�������:
	pszDevName �豸����ʹ����CN��
	uiPINType	����
	pszOldPin ������
	pszNewPin ������
	puiRetryCount ���Դ���
	�������:
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int __stdcall WTF_ChangePIN(const char *pszDevName, unsigned int uiPINType, const char *pszOldPin, const char * pszNewPin, unsigned int *puiRetryCount);
	/*
	��������:	�޸�����ͨ��֤�����ԣ�ǩ��֤������豸��
	��������:	WTF_ChangePINByCertProperty
	�������:
	pCertProperty ֤������  // SMC�ӿڲ��ҳ���֮��Ľṹ��
	pszPIN	����
	pbData  ����
	uiDataLen ����
	�������:
	pSignature ǩ��ֵ
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int __stdcall WTF_ChangePINByCertProperty(SK_CERT_DESC_PROPERTY * pCertProperty, unsigned int uiPINType, const char * pszOldPin, const char * pszNewPin, unsigned int *puiRetryCount);


	typedef unsigned int (CallBackCfcaGetEncryptPIN)(void * param, unsigned char *pbRandom, unsigned int uiRandomLen, unsigned char *pbEncryptPIN, unsigned int *puiEncryptPINLen);


	typedef struct _OPST_HANDLE_ARGS {
		void * ghInst;
		void * hDev;
		void * hAPP;
		void * hCon;
	}OPST_HANDLE_ARGS;

	COMMON_API unsigned int __stdcall WTF_SM2SignInitializeVerifyPINByCertProperty(SK_CERT_DESC_PROPERTY * pCertProperty, unsigned int uiPINType, CallBackCfcaGetEncryptPIN GetEncryptPIN, OPST_HANDLE_ARGS * args, unsigned int *puiRetryCount);
	COMMON_API unsigned int __stdcall WTF_SM2SignDigestProcess(OPST_HANDLE_ARGS *args, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int __stdcall WTF_SM2SignFinalize(OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall WTF_SM2SignDigestForHengBao(SK_CERT_DESC_PROPERTY * pCertProperty, unsigned int uiPINType, CallBackCfcaGetEncryptPIN GetEncryptPIN, void * pArgs/*NULL is able*/, unsigned int *puiRetryCount, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);



	COMMON_API unsigned int __stdcall WTF_SM2SignInitializeV2(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS *args);
	COMMON_API unsigned int __stdcall WTF_SM2SignDigestProcessV2(SK_CERT_DESC_PROPERTY * pCertProperty, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int __stdcall WTF_SM2SignFinalizeV2(OPST_HANDLE_ARGS *args);

	COMMON_API unsigned int __stdcall WTF_ArgsGet(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall WTF_ArgsPut(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args);
	COMMON_API unsigned int __stdcall WTF_ArgsClr();

	COMMON_API HINSTANCE __stdcall WTF_LoadLibrary(char * pszDllPath);

	/*
	��������:	��ȡ�豸��Ϣ
	��������:	WTF_GetDevInfoByCertProperty
	�������:
	pCertProperty ֤������  // SMC�ӿڲ��ҳ���֮��Ľṹ��
	�������:
	pDevInfo �豸��Ϣ
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int __stdcall WTF_GetDevInfoByCertProperty(SK_CERT_DESC_PROPERTY * pCertProperty, DEVINFO *pDevInfo);


	/*
	��������:	��֤�豸���루ǩ��֤������豸��
	��������:	WTF_VerifyPIN
	�������:
	pszDevName �豸����
	uiPINType ����Ա/�û�
	pszPIN	����
	�������:
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	��֤�豸����
	*/
	COMMON_API unsigned int __stdcall WTF_VerifyPIN(const char *pszDevName, unsigned int uiPINType, const char *pszPin, unsigned int *puiRetryCount);
	/*
	��������:	��֤�豸����ͨ��֤�����ԣ�ǩ��֤������豸��
	��������:	WTF_VerifyPINByCertProperty
	�������:
	pCertProperty ֤������  // SMC�ӿڲ��ҳ���֮��Ľṹ��
	uiPINType ����Ա/�û�
	pszPIN	����
	�������:
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	��֤�豸����ͨ��֤������
	*/
	COMMON_API unsigned int __stdcall WTF_VerifyPINByCertProperty(SK_CERT_DESC_PROPERTY * pCertProperty, unsigned int uiPINType, const char * pszPin, unsigned int *puiRetryCount);


	/*
	��������:	SM2֤��ǩ��
	��������:	WTF_SM2SignDigest
	�������:
	pCertProperty ֤������  // SMC�ӿڲ��ҳ���֮��Ľṹ��
	pszPIN	����
	pbData  ����
	uiDataLen ����
	�������:
	pSignature ǩ��ֵ
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int __stdcall WTF_SM2SignDigest(SK_CERT_DESC_PROPERTY *pCertProperty, const char *pszPIN, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature, unsigned int *puiRetryCount);

	COMMON_API unsigned int __stdcall WTF_SM2SignDigestV2(
		SK_CERT_DESC_PROPERTY *pCertProperty,
		const char *pszPIN,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature, unsigned int *puiRetryCount);


	/*
	��������:	SM2��Կ��֤
	��������:	WTF_SM2VerifyDigest
	�������:
	pszDevName �豸����ʹ����CN��
	pSM2PubKeyBlob	��Կ
	pbData  ����
	uiDataLen ����
	pSignature ǩ��ֵ
	�������:
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int __stdcall WTF_SM2VerifyDigest(ECCPUBLICKEYBLOB* pSM2PubKeyBlob, BYTE *pbData, ULONG  uiDataLen, PECCSIGNATUREBLOB pSignature);


	/*
	��������:	��֤֤��ĺϷ���
	����:
	pszSKFName SKF��(NULL ����ȫ��SKF��)
	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� WTF_CERT_VERIFY_FLAG
	pbCert[IN]:  ����֤������,DER����
	uiCertLen[IN]:����֤�����ݳ��ȡ�
	����ֵ		0��  �ɹ���
	������ ������

	*/
	COMMON_API unsigned int __stdcall WTF_VerifyCert(unsigned int uiFlag, unsigned int uiAlgType, BYTE* pbCert, unsigned int uiCertLen);

	/*
	��������:	��֤��֤��ĺϷ���
	����:
	uiVerifyFlag
	(��֤��־) ��������λ�����
	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� WTF_CERT_VERIFY_FLAG
	pbCert[IN]:  ����֤������,DER����
	uiCertLen[IN]:����֤�����ݳ��ȡ�
	����ֵ		0��  �ɹ���
	������ ������

	*/
	COMMON_API unsigned int __stdcall WTF_VerifyRootCert(unsigned int uiVerifyFlag, unsigned int uiAlgType, BYTE* pbCert, unsigned int uiCertLen);


	/*
	��������:	֤���ȡ������Ϣ
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	�������:
	pCertProperty	֤������
	����ֵ		0��  �ɹ���
	������ ������

	*/
	COMMON_API unsigned int __stdcall WTF_CertGetProperty(BYTE* pbCert, unsigned int uiCertLen, SK_CERT_DESC_PROPERTY * pCertProperty);

	/*
	��������:	��ʾ֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	����ֵ		0��  �ɹ���
	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_UIDlgViewContext(BYTE* pbCert, unsigned int uiCertLen);

	/*
	��������:	��մ洢�����֤��
	�������:
	uiStoreID ��
	DEFAULT_SMC_STORE_SM2_ROOT_ID 1                // ��
	DEFAULT_SMC_STORE_SM2_USER_ID 2                // �û�
	DEFAULT_SMC_STORE_SM2_OTHERS_ID 3              // ����
	DEFAULT_SMC_STORE_SM2_CRL_ID 4                 // �����б�
	����ֵ		0��  �ɹ���
	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_ClearStore(unsigned int uiStoreID);

	/*
	��������:	�����֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	���������
	puiAlgType �㷨����
	����ֵ		0��  �ɹ���

	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_ImportCaCert(BYTE * pbCert, unsigned int uiCertLen, unsigned int * puiAlgType);

	/*
	��������:	�Ƿ��Ǹ�֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	����ֵ		0��  �ɹ���
	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_IsSM2RootCert(BYTE* pbCert, unsigned int uiCertLen, unsigned int * bIRoot);

	/*
	��������:	�����ϼ�CA֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	���������
	����ֵ		0��  �ɹ���
	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_FindSM2CACert(BYTE* pbCert, unsigned int uiCertLen,
		BYTE* pbCACert, unsigned int * uiCACertLen
	);

	/*
	��������:	����SKF����
	�������:
	pszSKFName: ����
	szVersion:�汾��
	���������
	����ֵ		0��  �ɹ���
	������		������
	*/
	COMMON_API unsigned int __stdcall WTF_FindSKFDriver(const char * pszSKFName, char * szVersion);


	/*
	��������:	��ӡ������־���ڲ�����ʹ�ñ���ͬʱ����־��¼��
	*/
	COMMON_API void WTF_PrintErrorMsg();

	/*
	��������:	ͨ��֤���������Ի�ȡ����֤��
	*/
	COMMON_API unsigned int __stdcall WTF_FindEnCertificateByCertDescProperty(
		_In_ SK_CERT_DESC_PROPERTY * pCertDescProperty, _Out_ unsigned char * pbCert, _Inout_ unsigned int * puiCertLen
	);

	COMMON_API unsigned int __stdcall WTF_SM2GetAgreementKey(
		_In_ SK_CERT_DESC_PROPERTY * pCertProperty,
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

	COMMON_API unsigned int __stdcall WTF_SM2GetAgreementKeyEx(
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