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
	afx_msg void OnBnClickedRadio1();
	afx_msg void OnBnClickedRadio2();
	afx_msg void OnBnClickedRadio3();

	int m_iSelXY;
	CEdit editXY;

	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
