#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2REQ 对话框

class CommonToolsDlgSM2REQ : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2REQ)

public:
	CommonToolsDlgSM2REQ(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgSM2REQ();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2REQ };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CEdit editPRV;
	CEdit editXY;

	CEdit editName;
	CEdit editEmail;
	CEdit editReq;
};
