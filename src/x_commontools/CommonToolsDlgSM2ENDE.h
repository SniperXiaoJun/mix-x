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
	
	afx_msg void OnBnClickedRadio1();
	afx_msg void OnBnClickedRadio2();
	afx_msg void OnBnClickedRadio3();
	afx_msg void OnBnClickedRadio4();
	afx_msg void OnBnClickedRadio5();
	afx_msg void OnBnClickedRadio6();

	int m_iSelIN;
	int m_iSelOUT;
	CEdit editIN;
	CEdit editOUT;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
