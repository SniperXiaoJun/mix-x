#pragma once
#include "afxwin.h"


// CommonToolsDlgBit 对话框

class CommonToolsDlgBit : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgBit)

public:
	CommonToolsDlgBit(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgBit();

// 对话框数据
	enum { IDD = IDD_DIALOG_BIT };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
	virtual BOOL OnInitDialog();
	CComboBox comboBoxType;
	CEdit edit_A;
	CEdit edit_B;
	CEdit edit_Out;
};
