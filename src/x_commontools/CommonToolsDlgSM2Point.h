#pragma once


// CommonToolsDlgSM2Point �Ի���

class CommonToolsDlgSM2Point : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2Point)

public:
	CommonToolsDlgSM2Point(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2Point();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2POINT };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CEdit editXY;

	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
};
