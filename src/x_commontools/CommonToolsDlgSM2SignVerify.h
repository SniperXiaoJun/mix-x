#pragma once


// CommonToolsDlgSM2SignVerify �Ի���

class CommonToolsDlgSM2SignVerify : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2SignVerify)

public:
	CommonToolsDlgSM2SignVerify(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2SignVerify();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2SIGNVERIFY };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()

public:
	CEdit editKEYS;

	CEdit editIN;
	CEdit editOUT;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
