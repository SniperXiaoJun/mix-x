
#ifndef _SMB_CS_API_H_
#define _SMB_CS_API_H_


#include "common.h"

typedef struct _SMB_CS_Data
{
	unsigned char *data;            // ����
	unsigned int length;            // ����
}SMB_CS_Data;

typedef struct _SMB_CS_CertificateAttr
{
	SMB_CS_Data stSKFName;			// SKF�ӿ�����
	SMB_CS_Data stDeviceName;			// �豸����
	SMB_CS_Data stApplicationName;	// Ӧ������
	SMB_CS_Data stContainerName;		// ��������
	SMB_CS_Data stCommonName;		    // ͨ���� ��ʾ�豸��
	SMB_CS_Data stSubject;    		// ������
	SMB_CS_Data stIsuue;              // �䷢��
	SMB_CS_Data stPublicKey;          // ��Կ
	SMB_CS_Data stSerialNumber;       // ���к�
	SMB_CS_Data stVendorData;         // �û��Զ�������
	unsigned char ucCertAlgType;	// ֤������
	unsigned char ucCertUsageType;	// ǩ������ 1 ǩ�� 2 ���� 3 ǩ������
	unsigned int ulVerify;			// ��֤��� WTF_CERT_VERIFY_RESULT_FLAG
	unsigned long long ulNotBefore;	// ��ʼ
	unsigned long long ulNotAfter;	// ��ֹ
}SMB_CS_CertificateAttr;

typedef struct _SMB_CS_CertificateFindAttr
{
	unsigned int uiFindFlag;        // ���ұ�� ����ѡ�λ�� 1 2 4 8 16 32 64 128 ... ֧��4*8=32�������� 32����ϲ���
	unsigned char ucCertAlgType;	// ֤������
	unsigned char ucCertUsageType;	// ǩ������
	SMB_CS_Data stSubject;    		// ������
	SMB_CS_Data stIsuue;              // �䷢��
	SMB_CS_Data stPublicKey;          // ��Կ
	SMB_CS_Data stSerialNumber;       // ���к�
	SMB_CS_Data stVendorData;         // �û��Զ�������
}SMB_CS_CertificateFindAttr;

typedef struct _SMB_CS_CertificateContent
{
	unsigned char *data;            // ����
	unsigned int length;            // ����
}SMB_CS_CertificateContent;

typedef struct _SMB_CS_CertificateContext
{
	SMB_CS_CertificateAttr     stAttr;      // ֤������
	SMB_CS_CertificateContent  stContent;   // ֤������
}SMB_CS_CertificateContext;

typedef struct _SMB_CS_CertificateContext_NODE
{
	SMB_CS_CertificateContext *ptr_data;
	struct _SMB_CS_CertificateContext_NODE *ptr_next;
}SMB_CS_CertificateContext_NODE;

typedef enum _EErr_SMB
{
	EErr_SMB_OK,									// �ɹ�
													// SKFERROR 0x0A000001-0x0A000032				// SKF�����뷶Χ
													// HRESULT  0x00000000-0x00015301				// ΢������뷶Χ
													// HRESULT  0x8000FFFF-0x802A010A				// ΢������뷶Χ
													// HRESULT  .....								// ΢������뷶Χ

													EErr_SMB_BASE = 0xF000FFFF,						// ��ʼ������
													EErr_SMB_DLL_REG_PATH,							// ע��·��
													EErr_SMB_DLL_PATH,								// ��ȡ������ַʧ��
													EErr_SMB_NO_APP,								// û��Ӧ��
													EErr_SMB_CREATE_STORE,							// �����洢��ʧ��
													EErr_SMB_OPEN_STORE,							// �򿪴洢��ʧ��
													EErr_SMB_NO_CERT_CHAIN,							// û��֤����
													EErr_SMB_EXPORT_PUK,							// ������Կʧ��
													EErr_SMB_VERIFY_CERT,							// ��֤֤��ǩ��ʧ��
													EErr_SMB_VERIFY_TIME,							// ��֤֤����Ч��ʧ��
													EErr_SMB_CREATE_CERT_CONTEXT,					// ����֤��������
													EErr_SMB_ADD_CERT_TO_STORE,						// ����֤��
													EErr_SMB_NO_RIGHT,								// û��Ȩ��
													EErr_SMB_SET_CERT_CONTEXT_PROPERTY,				// ��������
													EErr_SMB_INVALIDARG,                            // ��������
													EErr_SMB_MEM_LES,                               // �ڴ治��
													EErr_SMB_INVALID_ARG,                           // ��������
													EErr_SMB_FAIL = -1,

}EErr_SMB;

#ifdef __cplusplus
extern "C" {
#endif
	/*
	����֤��������
	*/
	COMMON_API unsigned int SMB_CS_CreateCtx(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
	�����û��Զ�������
	*/
	COMMON_API unsigned int SMB_CS_SetCtxVendor(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pVendor, unsigned int uiVendorLen);

	/*
	�ͷ�֤��������
	*/
	COMMON_API unsigned int SMB_CS_FreeCtx(SMB_CS_CertificateContext *pCertificateCtx, unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
	���֤�鵽���ݿ�
	*/
	COMMON_API unsigned int SMB_CS_AddCtxToDB(SMB_CS_CertificateContext *pCertificateCtx);

	/*
	�����ݿ�ɾ��֤����
	*/
	COMMON_API unsigned int SMB_CS_DelCtxFromDB(SMB_CS_CertificateContext *pCertificateCtx);

	/*
	������ݿ�
	*/
	COMMON_API unsigned int SMB_CS_ClrAllFromDB();

	/*
	�����ݿ����֤��
	*/
	COMMON_API unsigned int SMB_CS_FindCtxFromDB(SMB_CS_CertificateFindAttr *pCertificateFindAttr, SMB_CS_CertificateContext *pPreCertificateCtx, SMB_CS_CertificateContext **pCertificateCtx);

	/*
	�����ݿ����֤��
	*/
	COMMON_API unsigned int SMB_CS_EnumCtxFromDB(SMB_CS_CertificateContext *pPreCertificateCtx, SMB_CS_CertificateContext **pCertificateCtx);

	/*
	�����ݿ����SKF����
	*/
	COMMON_API unsigned int SMB_CS_EnumSKF(char * pszSKFNames, unsigned int * puiSKFNamesLen);

	/*
	�����ݿ��ȡSKF·��
	*/
	COMMON_API unsigned int SMB_CS_ReadSKFPath(const char * pszSKFName, char * pszDllPath, unsigned int *puiDllPathLen);
	
	/*
	�����ݿ��ȡSKFǩ������
	*/
	COMMON_API unsigned int SMB_CS_ReadSKFSignType(const char * pszSKFName, char * pszSignType, unsigned int *puiSignTypeLen);

#ifdef __cplusplus
}
#endif


#endif /*_SMB_CS_API_H_*/