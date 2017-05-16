#pragma once
#include "afxwin.h"


// CommonToolsDlgKeyEx dialog

class CommonToolsDlgKeyEx : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgKeyEx)

public:
	CommonToolsDlgKeyEx(CWnd* pParent = NULL);   // standard constructor
	virtual ~CommonToolsDlgKeyEx();

// Dialog Data
	enum { IDD = IDD_DIALOG_KEY_EX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
	CEdit m_editprv;
	CEdit m_editpub;
	CEdit m_editprvar;
	CEdit m_editpubar;
	CEdit m_editpubb;
	CEdit m_editpubbr;
	CEdit m_editida;
	CEdit m_editidb;
	CEdit m_editkey_len;
	CEdit m_editkey;
	CEdit m_editS1;
	CEdit m_editSA;
	afx_msg void OnCbnSelchangeCombo1();
	CComboBox m_comboA;
};
