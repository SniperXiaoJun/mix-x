#pragma once
#include "afxwin.h"


// CommonToolsDlgSM2Write �Ի���

class CommonToolsDlgSM2Write : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgSM2Write)

public:
	CommonToolsDlgSM2Write(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgSM2Write();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2WRITE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
	virtual BOOL OnInitDialog();
	CComboBox comboBoxType;
	CComboBox comboBoxEncode;
	CEdit editIN;
	CEdit editOUT;
	CEdit editPW;
	afx_msg void OnCbnSelchangeCombo1();
};
