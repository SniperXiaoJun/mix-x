// CommonToolsDlgHASH.cpp : implementation file
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgHASH.h"
#include "afxdialogex.h"
#include "encode_switch.h"
#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "gm-hash-bit.h"
#include "gm-ecc-512.h"
#include "sm2.h"
extern E_HASH_ALG_TYPE g_HashAlgType;


// CommonToolsDlgHASH dialog

IMPLEMENT_DYNAMIC(CommonToolsDlgHASH, CDialogEx)

CommonToolsDlgHASH::CommonToolsDlgHASH(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgHASH::IDD, pParent)
{

}

CommonToolsDlgHASH::~CommonToolsDlgHASH()
{
}

void CommonToolsDlgHASH::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT3, editKEYS);
	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT2, editOUT);
	DDX_Control(pDX, IDC_EDIT7, m_editID);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgHASH, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgHASH::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgHASH::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgHASH::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgHASH::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgHASH::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CommonToolsDlgHASH::OnBnClickedRadio4)
	ON_BN_CLICKED(IDC_RADIO5, &CommonToolsDlgHASH::OnBnClickedRadio5)
	ON_BN_CLICKED(IDC_RADIO6, &CommonToolsDlgHASH::OnBnClickedRadio6)
	ON_BN_CLICKED(IDCANCEL2, &CommonToolsDlgHASH::OnBnClickedCancel2)
	ON_EN_CHANGE(IDC_EDIT7, &CommonToolsDlgHASH::OnEnChangeEdit7)
END_MESSAGE_MAP()


// CommonToolsDlgHASH message handlers



void CommonToolsDlgHASH::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();
	wchar_t data_value_key[BUFFER_LEN_1K * 4] = {0};
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
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_key,&data_len_key);

	switch(m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
		{
			editIN.GetWindowText(file_in,BUFFER_LEN_1K * 4);

			FILE_READ("", (char *)utf8_encode(file_in).c_str(),(unsigned char *)data_value_in,&data_len_in);
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
	if(g_HashAlgType == E_HASH_ALG_ZY_256)
	{
		unsigned int ulRet = gm_hash_hash(data_len_in, (unsigned char *)data_value_in,
			(unsigned char *)data_value_out, EHASH_TYPE_ZY_HASH_256);

		data_len_out = GM_HASH_MIN_BYTES_LEN;

		if (ulRet)
		{
			MessageBox(L"操作失败");
		}
	}
	else if(g_HashAlgType == E_HASH_ALG_ZY_512)
	{
		unsigned int ulRet = gm_hash_hash(data_len_in, (unsigned char *)data_value_in,
			(unsigned char *)data_value_out, EHASH_TYPE_ZY_HASH_512);

		data_len_out = GM_HASH_MAX_BYTES_LEN;

		if (ulRet)
		{
			MessageBox(L"操作失败");
		}
	}
	else
	{
		unsigned int ulRet = gm_hash_hash(data_len_in, (unsigned char *)data_value_in,
			(unsigned char *)data_value_out, EHASH_TYPE_SM3);

		data_len_out = GM_HASH_MIN_BYTES_LEN;

		if (ulRet)
		{
			MessageBox(L"操作失败");
		}
	}


	switch(m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
		{
			editOUT.GetWindowText(file_out,BUFFER_LEN_1K * 4);

			FILE_WRITE("", (char *)utf8_encode(file_out).c_str(),(unsigned char *)data_value_out,data_len_out);
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
			OPF_Bin2WStr(data_value_out,data_len_out,data_value_tmp, &data_len_tmp);
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


void CommonToolsDlgHASH::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnCancel();
	wchar_t data_value_key[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;
	wchar_t data_value_in[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_in[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_out[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	unsigned char userID[BUFFER_LEN_1K] = {0};
	unsigned int userIDLen = BUFFER_LEN_1K;

	editKEYS.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_key,&data_len_key);


	m_editID.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)userID,&userIDLen);

	OpenSSL_Initialize();

	switch(m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
		{
			editIN.GetWindowText(file_in,BUFFER_LEN_1K * 4);

			FILE_READ("", (char *)utf8_encode(file_in).c_str(),(unsigned char *)data_value_in,&data_len_in);
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

	if(g_HashAlgType == E_HASH_ALG_ZY_256)
	{
		MessageBox(L"操作失败");
	}
	else if(g_HashAlgType == E_HASH_ALG_ZY_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
			unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

			memcpy(pubkey_xy_value, "\x04", 1);
			memcpy(pubkey_xy_value + 1 , data_value_key, GM_ECC_512_BYTES_LEN * 2);

			unsigned int ulRet = 0;
			
			if (0 == userIDLen)
			{
				ulRet = tcm_gmecc512_get_message_hash((unsigned char *)data_value_in,data_len_in,(unsigned char*)"1234567812345678", 16,(unsigned char *)pubkey_xy_value,GM_ECC_512_BYTES_LEN * 2+1,(unsigned char *)data_value_out,&data_len_out);
			}
			else
			{
				ulRet = tcm_gmecc512_get_message_hash((unsigned char *)data_value_in,data_len_in,userID,userIDLen,(unsigned char *)pubkey_xy_value,GM_ECC_512_BYTES_LEN * 2+1,(unsigned char *)data_value_out,&data_len_out);
			}

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
		else
		{
			MessageBox(L"操作成功");
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
			unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

			memcpy(pubkey_xy_value, "\x04", 1);
			memcpy(pubkey_xy_value + 1 , data_value_key, SM2_BYTES_LEN * 2);

			unsigned int ulRet = 0;

			if (0 == userIDLen)
			{
				ulRet = tcm_get_message_hash((unsigned char *)data_value_in,data_len_in,(unsigned char*)"1234567812345678", 16,(unsigned char *)pubkey_xy_value,SM2_BYTES_LEN * 2+1,(unsigned char *)data_value_out,&data_len_out);
			}
			else
			{
				ulRet = tcm_get_message_hash((unsigned char *)data_value_in,data_len_in,userID,userIDLen,(unsigned char *)pubkey_xy_value,SM2_BYTES_LEN * 2+1,(unsigned char *)data_value_out,&data_len_out);
			}

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
		else
		{
			MessageBox(L"操作成功");
		}
	}


	switch(m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
		{
			editOUT.GetWindowText(file_out,BUFFER_LEN_1K * 4);

			FILE_WRITE("", (char *)utf8_encode(file_out).c_str(),(unsigned char *)data_value_out,data_len_out);
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
			OPF_Bin2WStr(data_value_out,data_len_out,data_value_tmp, &data_len_tmp);
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

// CommonToolsDlgHASH ÏûÏ¢´¦Àí³ÌÐò

void CommonToolsDlgHASH::OnBnClickedRadio1()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgHASH::OnBnClickedRadio2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgHASH::OnBnClickedRadio3()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelIN = E_INPUT_TYPE_HEX;
}


void CommonToolsDlgHASH::OnBnClickedRadio4()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_FILE;
}


void CommonToolsDlgHASH::OnBnClickedRadio5()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_CHAR;
}


void CommonToolsDlgHASH::OnBnClickedRadio6()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelOUT = E_OUTPUT_TYPE_HEX;
}


void CommonToolsDlgHASH::OnBnClickedCancel2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnCancel();
	wchar_t data_value_key[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;
	wchar_t data_value_in[BUFFER_LEN_1K * 4] = {0};
	char data_value_out[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_in[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_out[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	unsigned char userID[BUFFER_LEN_1K] = {0};
	unsigned int userIDLen = BUFFER_LEN_1K;

	editKEYS.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_key,&data_len_key);


	m_editID.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)userID,&userIDLen);


	OpenSSL_Initialize();

	switch(m_iSelIN)
	{
	case E_INPUT_TYPE_FILE:
		{
			editIN.GetWindowText(file_in,BUFFER_LEN_1K * 4);

			FILE_READ("", (char *)utf8_encode(file_in).c_str(),(unsigned char *)data_value_in,&data_len_in);
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

	if(g_HashAlgType == E_HASH_ALG_ZY_256)
	{
		MessageBox(L"操作失败");
	}
	else if(g_HashAlgType == E_HASH_ALG_ZY_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			unsigned int pubkey_xy_len = 2 * GM_ECC_512_BYTES_LEN + 1;
			unsigned char pubkey_xy_value[2 * GM_ECC_512_BYTES_LEN + 1] = {0};

			memcpy(pubkey_xy_value, "\x04", 1);
			memcpy(pubkey_xy_value + 1 , data_value_key, GM_ECC_512_BYTES_LEN * 2);

			unsigned int ulRet = 0;

			if (userIDLen == 0)
			{
				ulRet =	tcm_gmecc512_get_usrinfo_value((unsigned char*)"1234567812345678", 16,(unsigned char *)pubkey_xy_value,GM_ECC_512_BYTES_LEN * 2+1,(unsigned char *)data_value_out, EHASH_TYPE_ZY_HASH_512);

			}
			else
			{
				ulRet =	tcm_gmecc512_get_usrinfo_value(userID,userIDLen,(unsigned char *)pubkey_xy_value,GM_ECC_512_BYTES_LEN * 2+1,(unsigned char *)data_value_out, EHASH_TYPE_ZY_HASH_512);
			}
			
			data_len_out = 64;

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
		else
		{
			MessageBox(L"操作成功");
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			unsigned int pubkey_xy_len = 2 * SM2_BYTES_LEN + 1;
			unsigned char pubkey_xy_value[2 * SM2_BYTES_LEN + 1] = {0};

			memcpy(pubkey_xy_value, "\x04", 1);
			memcpy(pubkey_xy_value + 1 , data_value_key, SM2_BYTES_LEN * 2);


			unsigned int ulRet = 0;

			if (userIDLen == 0)
			{
				ulRet =	tcm_get_usrinfo_value((unsigned char*)"1234567812345678", 16,(unsigned char *)pubkey_xy_value,SM2_BYTES_LEN * 2+1,(unsigned char *)data_value_out);
			}
			else
			{
				ulRet =	tcm_get_usrinfo_value(userID,userIDLen,(unsigned char *)pubkey_xy_value,SM2_BYTES_LEN * 2+1,(unsigned char *)data_value_out);
			}

			data_len_out = 32;

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
		else
		{
			MessageBox(L"操作成功");
		}
	}


	switch(m_iSelOUT)
	{
	case E_OUTPUT_TYPE_FILE:
		{
			editOUT.GetWindowText(file_out,BUFFER_LEN_1K * 4);

			FILE_WRITE("", (char *)utf8_encode(file_out).c_str(),(unsigned char *)data_value_out,data_len_out);
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
			OPF_Bin2WStr((unsigned char *)data_value_out,data_len_out,data_value_tmp, &data_len_tmp);
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


void CommonToolsDlgHASH::OnEnChangeEdit7()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialogEx::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}
