#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2REQ �Ի���

class CommonToolsDlgSM2REQ : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2REQ)

public:
	CommonToolsDlgSM2REQ(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2REQ();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2REQ };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CEdit editPRV;
	CEdit editXY;

	CEdit editName;
	CEdit editEmail;
	CEdit editReq;
};
