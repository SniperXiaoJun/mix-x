#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2KEY 对话框

class CommonToolsDlgSM2KEY : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2KEY)

public:
	CommonToolsDlgSM2KEY(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgSM2KEY();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2KEY };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();


	int m_iSelXY;
	int m_iSelPRV;
	CEdit editXY;
	CEdit editPRV;
	afx_msg void OnBnClickedRadio1();
	afx_msg void OnBnClickedRadio2();
	afx_msg void OnBnClickedRadio3();
	afx_msg void OnBnClickedRadio4();
	afx_msg void OnBnClickedRadio5();
	afx_msg void OnBnClickedRadio6();
};
