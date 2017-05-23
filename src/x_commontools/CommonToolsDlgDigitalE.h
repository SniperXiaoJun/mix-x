#pragma once
#include "afxwin.h"


// CommonToolsDlgDigitalE 对话框

class CommonToolsDlgDigitalE : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgDigitalE)

public:
	CommonToolsDlgDigitalE(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgDigitalE();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2DigitalE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
	CEdit m_editPK;
	CEdit m_editDigitalE;
};
