// CommonToolsDlgSM2SignVerify.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2SignVerify.h"
#include "afxdialogex.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "encode_switch.h"
#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;



// CommonToolsDlgSM2SignVerify ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2SignVerify, CDialogEx)

	CommonToolsDlgSM2SignVerify::CommonToolsDlgSM2SignVerify(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2SignVerify::IDD, pParent)
{
	m_iSelOUT = -1;
	m_iSelIN = -1;
}

CommonToolsDlgSM2SignVerify::~CommonToolsDlgSM2SignVerify()
{
}

void CommonToolsDlgSM2SignVerify::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT3, editKEYS);
	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT2, editOUT);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2SignVerify, CDialogEx)
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio4)
	ON_BN_CLICKED(IDC_RADIO5, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio5)
	ON_BN_CLICKED(IDC_RADIO6, &CommonToolsDlgSM2SignVerify::OnBnClickedRadio6)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2SignVerify::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2SignVerify::OnBnClickedCancel)
END_MESSAGE_MAP()


// CommonToolsDlgSM2SignVerify ÏûÏ¢´¦Àí³ÌÐò

void CommonToolsDlgSM2SignVerify::OnBnClickedRadio1()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgSM2SignVerify::OnBnClickedRadio2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgSM2SignVerify::OnBnClickedRadio3()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_HEX;
}


void CommonToolsDlgSM2SignVerify::OnBnClickedRadio4()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_FILE;
}


void CommonToolsDlgSM2SignVerify::OnBnClickedRadio5()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_CHAR;
}


void CommonToolsDlgSM2SignVerify::OnBnClickedRadio6()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_HEX;
}

void CommonToolsDlgSM2SignVerify::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();
	unsigned char data_value_key[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	wchar_t data_value_in[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_in[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_out[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	editKEYS.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, data_value_key,&data_len_key);

	switch(m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
		{
			editIN.GetWindowText(file_in,BUFFER_LEN_1K * 4);

			FILE_READ("", utf8_encode(file_in).c_str(),(unsigned char *)data_value_in,&data_len_in);
		}
		break;
	case E_INPUT_TYPE_CHAR:
		{
			editIN.GetWindowText(data_value_in,BUFFER_LEN_1K * 4);
			data_len_in = wcslen(data_value_in);
		}
		break;
	case E_INPUT_TYPE_HEX:
		{
			editIN.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
			data_len_tmp = wcslen(data_value_tmp);

			OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_in, &data_len_in);
		}
		break;
	default:
		{
			editIN.GetWindowText(data_value_in,BUFFER_LEN_1K * 4);
			data_len_in = wcslen(data_value_in);
		}
		break;
	}
	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN)
		{
			unsigned int ulRet = OpenSSL_GMECC512SignDigest(
				(unsigned char *)data_value_in,data_len_in,
				(unsigned char *)data_value_key,GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_out,&data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN)
		{
			unsigned int ulRet = OpenSSL_SM2SignDigest(
				(unsigned char *)data_value_in,data_len_in,
				(unsigned char *)data_value_key,SM2_BYTES_LEN,
				(unsigned char *)data_value_out,&data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}
	

	switch(m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
		{
			editOUT.GetWindowText(file_out,BUFFER_LEN_1K * 4);

			FILE_WRITE("",utf8_encode(file_out).c_str(),data_value_out,data_len_out);
		}
		break;
	case E_OUTPUT_TYPE_CHAR:
		{
			editOUT.SetWindowText(utf8_decode((char*)data_value_out).c_str());
		}
		break;
	case E_OUTPUT_TYPE_HEX:
		{
			data_len_tmp = BUFFER_LEN_1K * 4;
			OPF_Bin2WStr(data_value_out,data_len_out, data_value_tmp, &data_len_tmp);
			editOUT.SetWindowText(data_value_tmp);
		}
		break;
	default:
		{
			editOUT.SetWindowText(utf8_decode((char*)data_value_out).c_str());
		}
		break;
	}
	OpenSSL_Finalize();
}


void CommonToolsDlgSM2SignVerify::OnBnClickedCancel()
{

	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnCancel();
	wchar_t data_value_key[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;
	wchar_t data_value_in[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_out[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_in[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_out[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	editKEYS.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_key,&data_len_key);

	OpenSSL_Initialize();

	switch(m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
		{
			editIN.GetWindowText(file_in,BUFFER_LEN_1K * 4);

			FILE_READ("", utf8_encode(file_in).c_str(),(unsigned char *)data_value_in,&data_len_in);
		}
		break;
	case E_INPUT_TYPE_CHAR:
		{
			editIN.GetWindowText(data_value_in,BUFFER_LEN_1K * 4);
			data_len_in = wcslen(data_value_in);
		}
		break;
	case E_INPUT_TYPE_HEX:
		{
			editIN.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
			data_len_tmp = wcslen(data_value_tmp);

			OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_in, &data_len_in);
		}
		break;
	default:
		{
			editIN.GetWindowText(data_value_in,BUFFER_LEN_1K * 4);
			data_len_in = wcslen(data_value_in);
		}
		break;
	}

	switch(m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
		{
			editOUT.GetWindowText(file_out,BUFFER_LEN_1K * 4);

			FILE_READ("", utf8_encode(file_out).c_str(),(unsigned char *)data_value_out,&data_len_out);
		}
		break;
	case E_OUTPUT_TYPE_CHAR:
		{
			editOUT.GetWindowText(data_value_out,BUFFER_LEN_1K * 4);
		}
		break;
	case E_OUTPUT_TYPE_HEX:
		{
			data_len_tmp = BUFFER_LEN_1K * 4;

			editOUT.GetWindowText(data_value_tmp, data_len_tmp);

			data_len_tmp = wcslen(data_value_tmp);

			OPF_WStr2Bin(data_value_tmp, data_len_tmp,(unsigned char *)data_value_out,&data_len_out);
		}
		break;
	default:
		{
			editOUT.GetWindowText(data_value_out,BUFFER_LEN_1K * 4);
		}
		break;
	}

	unsigned int ulRet = -1;

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			ulRet = OpenSSL_GMECC512VerifyDigest(
				(unsigned char *)data_value_in,data_len_in, 
				(unsigned char *)data_value_out,data_len_out,
				(unsigned char *)data_value_key,GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_key + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN
				);
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			ulRet = OpenSSL_SM2VerifyDigest(
				(unsigned char *)data_value_in,data_len_in, 
				(unsigned char *)data_value_out,data_len_out,
				(unsigned char *)data_value_key,SM2_BYTES_LEN,
				(unsigned char *)data_value_key + SM2_BYTES_LEN,SM2_BYTES_LEN
				);
		}
	}


	
	OpenSSL_Finalize();

	if (0 == ulRet)
	{
		MessageBox(L"操作成功");
	}
	else
	{
		MessageBox(L"操作失败");
	}
}
