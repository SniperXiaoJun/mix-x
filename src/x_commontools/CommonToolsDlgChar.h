#pragma once
#include "afxwin.h"


// CommonToolsDlgChar 对话框

class CommonToolsDlgChar : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgChar)

public:
	CommonToolsDlgChar(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgChar();

// 对话框数据
	enum { IDD = IDD_DIALOG_CHAR };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
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
};
