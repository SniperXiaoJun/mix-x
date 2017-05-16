#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2CERT 对话框

class CommonToolsDlgSM2CERT : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2CERT)

public:
	CommonToolsDlgSM2CERT(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgSM2CERT();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2CERT };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	CEdit editPRV;
	CEdit editXY;
	CEdit editROOTCER;
	CEdit editCSR;
	CEdit editCER;
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnBnClickedCancel();
	virtual BOOL OnInitDialog();
	CComboBox comboBoxType;
	CEdit editDate;
	CEdit editSN;
	afx_msg void OnBnClickedOk2();
};
