#pragma once
#include "afxwin.h"


// CommonToolsDlgDigitalE �Ի���

class CommonToolsDlgDigitalE : public CDialogEx
{
	DECLARE_DYNAMIC(CommonToolsDlgDigitalE)

public:
	CommonToolsDlgDigitalE(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CommonToolsDlgDigitalE();

// �Ի�������
	enum { IDD = IDD_DIALOG_SM2DigitalE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedCancel();
	CEdit m_editPK;
	CEdit m_editDigitalE;
};
