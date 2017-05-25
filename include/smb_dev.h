#ifndef __SMB_DEV_H__

#define __SMB_DEV_H__

#include <windows.h>
#include "smb_cs.h"
#include "SKFInterface.h"


// ֤��(��Կ���ͱ�־) ��������λ�����
typedef enum _SMB_DEV_CERT_ALG_FLAG
{
	CERT_ALG_RSA_FLAG = 0x00000001,		// RSA֤��
	CERT_ALG_SM2_FLAG = 0x00000002,		// SM2֤��

}SMB_DEV_CERT_ALG_TYPE;

// ֤��(ǩ��|���ܱ�־) ��������λ�����
typedef enum _SMB_DEV_CERT_USAGE_FLAG
{
	CERT_SIGN_FLAG = 0x00000001,		// ǩ��֤��
	CERT_EX_FLAG = 0x00000002,		// ����֤��

}SMB_DEV_CERT_USAGE_FLAG;

// ֤��(��֤��־) ��������λ�����
typedef enum _SMB_DEV_CERT_VERIFY_FLAG
{
	CERT_NOT_VERIFY_FLAG = 0x00000000,		// ����֤
	CERT_VERIFY_TIME_FLAG = 0x00000001,		// ʹ�ñ��ص�ǰʱ����֤��Ч��
	CERT_VERIFY_CHAIN_FLAG = 0x00000002,		// ��֤֤�����Լ�ǩ��
	CERT_VERIFY_CRL_FLAG = 0x00000004,		// ��δʵ��

}SMB_DEV_CERT_VERIFY_FLAG;

// ��֤���
typedef enum _SMB_DEV_CERT_VERIFY_RESULT_FLAG
{
	CERT_VERIFY_RESULT_FLAG_OK = 0x00000000,		// ��֤�ɹ�
	CERT_VERIFY_RESULT_TIME_INVALID = 0x00000001,		// ������Ч��
	CERT_VERIFY_RESULT_CHAIN_INVALID = 0x00000002,		// ֤�����쳣
	CERT_VERIFY_RESULT_SIGN_INVALID = 0x00000003,		// �Ƿ��û�֤��
	CERT_VERIFY_RESULT_CRL_INVALID = 0x00000004,		// ��δ����

}SMB_DEV_CERT_VERIFY_RESULT_FLAG;


typedef enum _SMB_DEV_CERT_FILTER_FLAG
{
	CERT_FILTER_FLAG_FALSE = 0x00000000,		// ������
	CERT_FILTER_FLAG_TRUE = 0x00000001,		// ����
}SMB_DEV_CERT_FILTER_FLAG;


#ifdef __cplusplus
extern "C" {
#endif

	/*
	��������:	ͨ��SKFö��֤��
	��������:	SMB_DEV_EnumCertBySKF
	�������:
		pszSKFName SKF��(����ָ��)
		uiKeyFlag
		֤��(��Կ���ͱ�־) ��������λ�����
		�μ� SMB_DEV_CERT_ALG_FLAG
		uiSignFlag
		֤��(ǩ��|���ܱ�־) ��������λ�����
		�μ� SMB_DEV_CERT_SIGN_FLAG
		uiVerifyFlag
		֤��(��֤��־) ��������λ�����
		�μ� SMB_DEV_CERT_VERIFY_FLAG
		�������:
		pvCertsValue	��֤�鴮
		puiCertsLen		����
	����ֵ: 0:�ɹ� ����:������
	*/
	COMMON_API unsigned int SMB_DEV_EnumCertBySKF(const char*pszSKFName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	��������:	ö��֤��
	��������:	SMB_DEV_EnumCert
	�������:
		pszSKFName SKF��(NULL ����ȫ��SKF��)
		uiKeyFlag
		֤��(��Կ���ͱ�־) ��������λ�����
		�μ� SMB_DEV_CERT_ALG_FLAG
		uiSignFlag
		֤��(ǩ��|���ܱ�־) ��������λ�����
		�μ� SMB_DEV_CERT_SIGN_FLAG
		uiVerifyFlag
		֤��(��֤��־) ��������λ�����
		�μ� SMB_DEV_CERT_VERIFY_FLAG
		�������:
		pvCertsValue	��֤�鴮
		puiCertsLen		����
	����ֵ: 0:�ɹ� ����:������
	*/
	COMMON_API unsigned int SMB_DEV_EnumCert(const char *pszSKFName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int uiKeyFlag, unsigned int uiSignFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag);

	/*
	��������:	�޸�����ͨ��֤�����ԣ�ǩ��֤������豸��
	��������:	SMB_DEV_ChangePINByCertAttr
	�������:
	pCertAttr ֤������// SMC�ӿڲ��ҳ���֮��Ľṹ��
	pszPIN	����
	pbData����
	uiDataLen ����
	�������:
	pSignature ǩ��ֵ
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int SMB_DEV_ChangePINByCertAttr(SMB_CS_CertificateAttr *pCertAttr, unsigned int uiPINType, const char*pszOldPin, const char*pszNewPin, ULONG *puiRetryCount);

	/*
	���ز��ͷź������
	*/
	COMMON_API HINSTANCE SMB_DEV_LoadLibrary(char*pszDllPath);

	/*
	ͨ��֤���������Ի�ȡ����֤��
	*/
	COMMON_API unsigned int SMB_DEV_FindEnCertificateByCertAttr(
		_In_ SMB_CS_CertificateAttr *pCertDescProperty, _Out_ unsigned char *pbCert, _Inout_ unsigned int *puiCertLen
	);

	typedef struct _OPST_HANDLE_ARGS {
		void*ghInst;
		void*hDev;
		void*hAPP;
		void*hCon;
	}OPST_HANDLE_ARGS;	
	
	COMMON_API unsigned int SMB_DEV_SM2SignDigestProcess(OPST_HANDLE_ARGS *args, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int SMB_DEV_SM2SignFinalize(OPST_HANDLE_ARGS *args);
	
	COMMON_API unsigned int SMB_DEV_SM2SignInitializeV2(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS *args);
	COMMON_API unsigned int SMB_DEV_SM2SignDigestProcessV2(SMB_CS_CertificateAttr*pCertAttr, BYTE *pbData, unsigned int uiDataLen, PECCSIGNATUREBLOB pSignature);
	COMMON_API unsigned int SMB_DEV_SM2SignFinalizeV2(OPST_HANDLE_ARGS *args);

	COMMON_API unsigned int SMB_DEV_ArgsGet(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS*args);
	COMMON_API unsigned int SMB_DEV_ArgsPut(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS*args);
	COMMON_API unsigned int SMB_DEV_ArgsClr();

	/*
	��������:	��ȡ�豸��Ϣ
	��������:	SMB_DEV_GetDevInfoByCertAttr
	�������:
	pCertAttr ֤������// SMC�ӿڲ��ҳ���֮��Ľṹ��
	�������:
	pDevInfo �豸��Ϣ
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int SMB_DEV_GetDevInfoByCertAttr(SMB_CS_CertificateAttr*pCertAttr, DEVINFO *pDevInfo);

	/*
	��������:	��֤�豸����ͨ��֤�����ԣ�ǩ��֤������豸��
	��������:	SMB_DEV_VerifyPINByCertAttr
	�������:
	pCertAttr ֤������// SMC�ӿڲ��ҳ���֮��Ľṹ��
	uiPINType ����Ա/�û�
	pszPIN	����
	�������:
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	��֤�豸����ͨ��֤������
	*/
	COMMON_API unsigned int SMB_DEV_VerifyPINByCertAttr(SMB_CS_CertificateAttr*pCertAttr, unsigned int uiPINType, char*pszPin, ULONG *puiRetryCount);

	/*
	��������:	SM2֤��ǩ��
	��������:	SMB_DEV_SM2SignDigest
	�������:
	pCertAttr ֤������// SMC�ӿڲ��ҳ���֮��Ľṹ��
	pszPIN	����
	pbData����
	uiDataLen ����
	�������:
	pSignature ǩ��ֵ
	puiRetryCount ���Դ���
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int SMB_DEV_SM2SignDigest(
		SMB_CS_CertificateAttr *pCertAttr,
		char *pszPIN,
		BYTE *pbDigest, unsigned int uiDigestLen,
		BYTE *pbData, unsigned int uiDataLen,
		PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount);

	/*
	��������:	SM2��Կ��֤
	��������:	SMB_DEV_SM2VerifyDigest
	�������:
	pszDevName �豸����ʹ����CN��
	pSM2PubKeyBlob	��Կ
	pbData����
	uiDataLen ����
	pSignature ǩ��ֵ
	�������:
	����ֵ:
	ʧ�ܣ�
	��������:	�޸�����
	*/
	COMMON_API unsigned int SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB *pSM2PubKeyBlob, BYTE *pbData, ULONG uiDataLen, PECCSIGNATUREBLOB pSignature);

	/*
	��������:	��֤֤��ĺϷ���
	����:
	pszSKFName SKF��(NULL ����ȫ��SKF��)
	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� SMB_DEV_CERT_VERIFY_FLAG
	pbCert[IN]:����֤������,DER����
	uiCertLen[IN]:����֤�����ݳ��ȡ�
	����ֵ		0���ɹ���
	������ ������
	*/
	COMMON_API unsigned int SMB_DEV_VerifyCert(unsigned int uiFlag, unsigned int uiAlgType, BYTE *pbCert, unsigned int uiCertLen);

	/*
	��������:	��֤��֤��ĺϷ���
	����:
	uiVerifyFlag
	(��֤��־) ��������λ�����
	uiVerifyFlag
	֤��(��֤��־) ��������λ�����
	�μ� SMB_DEV_CERT_VERIFY_FLAG
	pbCert[IN]:����֤������,DER����
	uiCertLen[IN]:����֤�����ݳ��ȡ�
	����ֵ		0���ɹ���
	������ ������
	*/
	COMMON_API unsigned int SMB_DEV_VerifyRootCert(unsigned int uiVerifyFlag, unsigned int uiAlgType, BYTE *pbCert, unsigned int uiCertLen);

	/*
	��������:	֤���ȡ������Ϣ
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	�������:
	pCertAttr	֤������
	����ֵ		0���ɹ���
	������ ������

	*/
	COMMON_API unsigned int SMB_DEV_CertFillAttr(BYTE *pbCert, unsigned int uiCertLen, SMB_CS_CertificateAttr*pCertAttr);

	/*
	��������:	��ʾ֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	����ֵ		0���ɹ���
	������		������
	*/
	COMMON_API unsigned int SMB_DEV_UIDlgViewContext(BYTE *pbCert, unsigned int uiCertLen);

	/*
	��������:	�����֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	���������
	puiAlgType �㷨����
	����ֵ		0���ɹ���

	������		������
	*/
	COMMON_API unsigned int SMB_DEV_ImportCaCert(BYTE*pbCert, unsigned int uiCertLen, unsigned int*puiAlgType);

	/*
	��������:	�Ƿ��Ǹ�֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	����ֵ		0���ɹ���
	������		������
	*/
	COMMON_API unsigned int SMB_DEV_IsSM2RootCert(BYTE *pbCert, unsigned int uiCertLen, unsigned int*bIRoot);

	/*
	��������:	�����ϼ�CA֤��
	�������:
	pbCert[IN]:		����֤������,DER����
	uiCertLen[IN]:	����֤�����ݳ��ȡ�
	���������
	����ֵ		0���ɹ���
	������		������
	*/
	COMMON_API unsigned int SMB_DEV_FindSM2CACert(BYTE *pbCert, unsigned int uiCertLen,
		BYTE *pbCACert, unsigned int*uiCACertLen
	);



	COMMON_API unsigned int SMB_DEV_SM2GetAgreementKey(
		_In_ SMB_CS_CertificateAttr*pCertAttr,
		_In_ ULONG ulAlgId,
		_Out_ ECCPUBLICKEYBLOB *pTempECCPubKeyBlobA,
		_In_ BYTE *pbIDA,
		_In_ ULONG ulIDALen,
		_In_ ECCPUBLICKEYBLOB *pECCPubKeyBlobB,
		_In_ ECCPUBLICKEYBLOB *pTempECCPubKeyBlobB,
		_In_ BYTE *pbIDB,
		_In_ ULONG ulIDBLen,
		_Out_ BYTE *pbAgreementKey,
		_Inout_ ULONG *pulAgreementKeyLen,
		_In_ const char*pszPIN,
		_Inout_ ULONG*puiRetryCount);

	COMMON_API unsigned int SMB_DEV_SM2GetAgreementKeyEx(
		_In_ BYTE *pbCert,
		_In_ unsigned int uiCertLen,
		_In_ int uiAlgId,
		_Out_ BYTE *pbTempECCPubKeyBlobA,
		_Inout_ int *puiTempECCPubKeyBlobALen,
		_In_ BYTE *pbIDA,
		_In_ int uiIDALen,
		_In_ BYTE *pbECCPubKeyBlobB,
		_In_ int uiECCPubKeyBlobBLen,
		_In_ BYTE *pbTempECCPubKeyBlobB,
		_In_ int uiTempECCPubKeyBlobBLen,
		_In_ BYTE *pbIDB,
		_In_ int uiIDBLen,
		_Out_ BYTE *pbAgreementKey,
		_Inout_ int *puiAgreementKeyLen,
		_In_ const char*pszPIN,
		_Inout_ int*puiRetryCount);

	/*
	��������:	ö���豸
	��������:	SMB_DEV_EnumDev
	�������:
	�������:
	pszDevsName		���ַ�������ʾ����豸��,��ͬ���豸��֮����0x00�������0x0000��ʾ���ַ�������
	puiDevsNameLen	���ض��ַ�������
	����ֵ:
	ʧ�ܣ�
	��������:	ö���豸
	*/
	COMMON_API unsigned int SMB_DEV_EnumDev(char *pszDevsName, unsigned int *puiDevsNameLen);

	/*
	��������:	�޸����루ǩ��֤������豸��
	��������:	SMB_DEV_ChangePIN
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
	COMMON_API unsigned int SMB_DEV_ChangePIN(const char *pszDevName, unsigned int uiPINType, const char *pszOldPin, const char*pszNewPin, ULONG *puiRetryCount);

	/*
	��������:	��֤�豸���루ǩ��֤������豸��
	��������:	SMB_DEV_VerifyPIN
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
	COMMON_API unsigned int SMB_DEV_VerifyPIN(const char *pszDevName, unsigned int uiPINType, char *pszPin, ULONG *puiRetryCount);
#ifdef __cplusplus
}
#endif



#endif