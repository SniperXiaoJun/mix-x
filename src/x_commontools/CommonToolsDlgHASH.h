#pragma once
#include "afxwin.h"


// CommonToolsDlgHASH dialog

class CommonToolsDlgHASH : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgHASH)

public:
	CommonToolsDlgHASH(CWnd* pParent = NULL);   // standard constructor
	virtual ~CommonToolsDlgHASH();

// Dialog Data
	enum { IDD = IDD_DIALOG_HASH };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();

	CEdit editKEYS;
	CEdit editIN;
	CEdit editOUT;
	afx_msg void OnBnClickedRadio1();
	afx_msg void OnBnClickedRadio2();
	afx_msg void OnBnClickedRadio3();
	afx_msg void OnBnClickedRadio4();
	afx_msg void OnBnClickedRadio5();
	afx_msg void OnBnClickedRadio6();

	int m_iSelIN;
	int m_iSelOUT;

	afx_msg void OnBnClickedCancel2();
	CEdit m_editID;
	afx_msg void OnEnChangeEdit7();
};
