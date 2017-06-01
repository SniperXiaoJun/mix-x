// CommonToolsDlgB64.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgB64.h"
#include "afxdialogex.h"
#include "modp_b64.h"
#include "common.h"
#include "CommonToolsTypedef.h"
#include "FILE_LOG.h"
#include "encode_switch.h"
#include "o_all_func_def.h"
// CommonToolsDlgB64 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgB64, CDialogEx)

CommonToolsDlgB64::CommonToolsDlgB64(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgB64::IDD, pParent)
{
	m_iSelOUT = -1;
	m_iSelIN = -1;
}

CommonToolsDlgB64::~CommonToolsDlgB64()
{
}

void CommonToolsDlgB64::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);

	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT2, editOUT);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgB64, CDialogEx)
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgB64::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgB64::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgB64::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CommonToolsDlgB64::OnBnClickedRadio4)
	ON_BN_CLICKED(IDC_RADIO5, &CommonToolsDlgB64::OnBnClickedRadio5)
	ON_BN_CLICKED(IDC_RADIO6, &CommonToolsDlgB64::OnBnClickedRadio6)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgB64::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgB64::OnBnClickedCancel)
END_MESSAGE_MAP()


// CommonToolsDlgB64 消息处理程序


void CommonToolsDlgB64::OnBnClickedRadio1()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelIN = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgB64::OnBnClickedRadio2()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelIN = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgB64::OnBnClickedRadio3()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelIN = E_INPUT_TYPE_HEX;
}


void CommonToolsDlgB64::OnBnClickedRadio4()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelOUT = E_OUTPUT_TYPE_FILE;
}


void CommonToolsDlgB64::OnBnClickedRadio5()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelOUT = E_OUTPUT_TYPE_CHAR;
}


void CommonToolsDlgB64::OnBnClickedRadio6()
{
	// TODO: 在此添加控件通知处理程序代码
	m_iSelOUT = E_OUTPUT_TYPE_HEX;
}

void CommonToolsDlgB64::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();

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
		MessageBox(L"选择类型", L"提示");

		return;
	}
	break;
	}

	data_len_out = modp_b64_encode((char *)data_value_out,(char *)data_value_in,data_len_in);

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
		MessageBox(L"选择类型", L"提示");

		return;
	}
	break;
	}
}


void CommonToolsDlgB64::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	// CDialogEx::OnCancel();

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
		MessageBox(L"选择类型", L"提示");

		return;
	}
	break;
	}

	data_len_out = modp_b64_decode((char *)data_value_out, (char *)data_value_in, data_len_in);

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
		MessageBox(L"选择类型", L"提示");

		return;
	}
	break;
	}
}
