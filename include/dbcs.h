
#ifndef _DBCS_API_H_
#define _DBCS_API_H_


#include "common.h"

typedef struct _DBCS_Data
{
	unsigned char *data;            // ����
	unsigned int length;            // ����
}DBCS_Data;

typedef struct _DBCS_CertificateAttr
{
	DBCS_Data stSKFName;			// SKF�ӿ�����
	DBCS_Data stDeviceName;			// �豸����
	DBCS_Data stApplicationName;	// Ӧ������
	DBCS_Data stContainerName;		// ��������
	DBCS_Data stCommonName;		    // ͨ���� ��ʾ�豸��
	DBCS_Data stSubject;    		// ������
	DBCS_Data stIsuue;              // �䷢��
	DBCS_Data stPublicKey;          // ��Կ
	DBCS_Data stSerialNumber;       // ���к�
	DBCS_Data stVendorData;         // �û��Զ�������
	unsigned char cAlgType;			// ֤������
    unsigned char cUsageType;		// ǩ������
	unsigned int ulVerify;			// ��֤��� WTF_CERT_VERIFY_RESULT_FLAG
	unsigned long long ulNotBefore;	// ��ʼ
	unsigned long long ulNotAfter;	// ��ֹ
}DBCS_CertificateAttr;

typedef struct _DBCS_CertificateFindAttr
{
	unsigned int uiFindFlag;        // ���ұ�� ����ѡ�λ�� 1 2 4 8 16 32 64 128 ... ֧��4*8=32�������� 32����ϲ���
	unsigned char cAlgType;			// ֤������
	unsigned char cUsageType;		// ǩ������
	DBCS_Data stSubject;    		// ������
	DBCS_Data stIsuue;              // �䷢��
	DBCS_Data stPublicKey;          // ��Կ
	DBCS_Data stSerialNumber;       // ���к�
	DBCS_Data stVendorData;         // �û��Զ�������
}DBCS_CertificateFindAttr;

typedef struct _DBCS_CertificateContent
{
	unsigned char *data;            // ����
	unsigned int length;            // ����
}DBCS_CertificateContent;

typedef struct _DBCS_CertificateContext
{
	DBCS_CertificateAttr     stAttr;      // ֤������
	DBCS_CertificateContent  stContent;   // ֤������
}DBCS_CertificateContext;

#ifdef __cplusplus
extern "C" {
#endif
	/*
		����֤��������
	*/
	COMMON_API unsigned int DBCS_CreateCtx(DBCS_CertificateContext *pCertificateCtx,unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
		�����û��Զ�������
	*/
	COMMON_API unsigned int DBCS_SetCtxVendor(DBCS_CertificateContext *pCertificateCtx,unsigned char *pVendor, unsigned int uiVendorLen);

	/*
		�ͷ�֤��������
	*/
	COMMON_API unsigned int DBCS_FreeCtx(DBCS_CertificateContext *pCertificateCtx,unsigned char *pCertificate, unsigned int uiCertificateLen);

	/*
		���֤�鵽���ݿ�
	*/
	COMMON_API unsigned int DBCS_AddCtxToDB(DBCS_CertificateContext *pCertificateCtx);

	/*
		�����ݿ�ɾ��֤����
	*/
	COMMON_API unsigned int DBCS_DelCtxFromDB(DBCS_CertificateContext *pCertificateCtx);

	/*
		������ݿ�
	*/
	COMMON_API unsigned int DBCS_ClrAllFromDB();

	/*
		�����ݿ����֤��	
	*/
	COMMON_API unsigned int DBCS_FindCtxFromDB(DBCS_CertificateFindAttr *pCertificateFindAttr,DBCS_CertificateContext *pPreCertificateCtx, DBCS_CertificateContext **pCertificateCtx);

	/*
		�����ݿ����֤��
	*/
	COMMON_API unsigned int DBCS_EnumCtxFromDB(DBCS_CertificateContext *pPreCertificateCtx, DBCS_CertificateContext **pCertificateCtx);

#ifdef __cplusplus
}
#endif


#endif /*_DBCS_API_H_*/