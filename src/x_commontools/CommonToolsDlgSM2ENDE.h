#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2ENDE �Ի���

class CommonToolsDlgSM2ENDE : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2ENDE)

public:
	CommonToolsDlgSM2ENDE(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2ENDE();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2ENDE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CEdit editKEYS;

	CEdit editIN;
	CEdit editOUT;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
