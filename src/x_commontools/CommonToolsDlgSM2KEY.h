#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2KEY �Ի���

class CommonToolsDlgSM2KEY : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2KEY)

public:
	CommonToolsDlgSM2KEY(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2KEY();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2KEY };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();

	CEdit editXY;
	CEdit editPRV;
};
