#pragma once


// CommonToolsDlgSM2Point 对话框

class CommonToolsDlgSM2Point : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2Point)

public:
	CommonToolsDlgSM2Point(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgSM2Point();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2POINT };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CEdit editXY;

	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
