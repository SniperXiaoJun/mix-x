#pragma once

#include "DemoBackDialog.h"

// CDialogSimple 对话框

class CDialogSimple : public CDialogEx
{
	DECLARE_DYNAMIC(CDialogSimple)

public:
	CDialogSimple(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CDialogSimple();

// 对话框数据
	enum { IDD = IDD_DIALOG_SIMPLE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();

	CDemoBackDialog *m_pDlg;
};
