// CommonToolsDlgChar.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgChar.h"
#include "afxdialogex.h"
#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "encode_switch.h"

// CommonToolsDlgChar �Ի���

IMPLEMENT_DYNAMIC(CommonToolsDlgChar, CDialogEx)

CommonToolsDlgChar::CommonToolsDlgChar(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgChar::IDD, pParent)
{
	m_iSelOUT = -1;
	m_iSelIN = -1;
}

CommonToolsDlgChar::~CommonToolsDlgChar()
{
}

void CommonToolsDlgChar::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT2, editOUT);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgChar, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgChar::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgChar::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgChar::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgChar::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgChar::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CommonToolsDlgChar::OnBnClickedRadio4)
	ON_BN_CLICKED(IDC_RADIO5, &CommonToolsDlgChar::OnBnClickedRadio5)
	ON_BN_CLICKED(IDC_RADIO6, &CommonToolsDlgChar::OnBnClickedRadio6)
END_MESSAGE_MAP()


// CommonToolsDlgChar ��Ϣ�������


void CommonToolsDlgChar::OnBnClickedOk()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	// CDialogEx::OnOK();

	unsigned char data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	wchar_t data_value_tmp[BUFFER_LEN_1K] = { 0 };

	switch (m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
	{
		editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		FILE_READ("", utf8_encode(data_value_tmp).c_str(), data_value_in, &data_len_in);
	}
	break;
	case E_INPUT_TYPE_CHAR:
	{
		editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		memcpy(data_value_in, utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()));

		data_len_in = strlen(utf8_encode(data_value_tmp).c_str());
	}
	break;
	case E_INPUT_TYPE_HEX:
	{
		editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_in, &data_len_in);
	}
	break;
	default:
	{
		MessageBox(L"ѡ������", L"��ʾ");

		return;
	}
	break;
	}

	OPF_Bin2Str(data_value_in, data_len_in, (char *)data_value_out, &data_len_out);

	switch (m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
	{
		editOUT.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		FILE_WRITE("", utf8_encode(data_value_tmp).c_str(), data_value_out, data_len_out);
	}
	break;
	case E_OUTPUT_TYPE_CHAR:
	case E_OUTPUT_TYPE_HEX:
	{
		editOUT.SetWindowText(utf8_decode((char *)data_value_out).c_str());
	}
	break;
	default:
	{
		MessageBox(L"ѡ������", L"��ʾ");

		return;
	}
	break;
	}
}


void CommonToolsDlgChar::OnBnClickedCancel()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	//CDialogEx::OnCancel();

	unsigned char data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	wchar_t data_value_tmp[BUFFER_LEN_1K] = { 0 };

	switch (m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
	{
		editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		FILE_READ("", utf8_encode(data_value_tmp).c_str(), (unsigned char *)data_value_in, &data_len_in);
	}
	break;
	case E_INPUT_TYPE_CHAR:
	case E_INPUT_TYPE_HEX:
	{
		editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		memcpy(data_value_in, utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()));

		data_len_in = strlen(utf8_encode(data_value_tmp).c_str());
	}
	break;
	default:
	{
		MessageBox(L"ѡ������", L"��ʾ");

		return;
	}
	break;
	}

	OPF_Str2Bin((char *)data_value_in, data_len_in, data_value_out, &data_len_out);

	switch (m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
	{
		editOUT.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

		FILE_WRITE("", (char *)utf8_encode(data_value_tmp).c_str(), data_value_out, data_len_out);
	}
	break;
	case E_OUTPUT_TYPE_CHAR:
	case E_OUTPUT_TYPE_HEX:
	{
		editOUT.SetWindowText(utf8_decode((char *)data_value_out).c_str());
	}
	break;
	default:
	{
		MessageBox(L"ѡ������", L"��ʾ");

		return;
	}
	break;
	}
}


void CommonToolsDlgChar::OnBnClickedRadio1()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelIN = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgChar::OnBnClickedRadio2()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelIN = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgChar::OnBnClickedRadio3()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelIN = E_INPUT_TYPE_HEX;
}


void CommonToolsDlgChar::OnBnClickedRadio4()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelOUT = E_OUTPUT_TYPE_FILE;
}


void CommonToolsDlgChar::OnBnClickedRadio5()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelOUT = E_OUTPUT_TYPE_CHAR;
}


void CommonToolsDlgChar::OnBnClickedRadio6()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_iSelOUT = E_OUTPUT_TYPE_HEX;
}
