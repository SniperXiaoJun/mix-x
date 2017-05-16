#pragma once


// CommonToolsDlgSM2SignVerify 对话框

class CommonToolsDlgSM2SignVerify : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2SignVerify)

public:
	CommonToolsDlgSM2SignVerify(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CommonToolsDlgSM2SignVerify();

// 对话框数据
	enum { IDD = IDD_DIALOG_SM2SIGNVERIFY };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()

public:
	CEdit editKEYS;

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
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
