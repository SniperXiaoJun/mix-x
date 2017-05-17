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


	afx_msg void OnBnClickedCancel2();
	CEdit m_editID;
};
