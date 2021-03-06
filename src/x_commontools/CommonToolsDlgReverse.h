#pragma once
#include "afxwin.h"


// CommonToolsDlgReverse 对话框

class CommonToolsDlgReverse : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgReverse)

public:
	CommonToolsDlgReverse(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgReverse();

// 对话框数据
	enum { IDD = IDD_DIALOG_REVERSE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CEdit editInput;
	CEdit editBitLen;
	CEdit editOutput;
	afx_msg void OnBnClickedOk();
	virtual BOOL OnInitDialog();
};
