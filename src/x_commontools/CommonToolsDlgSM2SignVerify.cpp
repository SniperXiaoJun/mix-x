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
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2SignVerify::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2SignVerify::OnBnClickedCancel)
END_MESSAGE_MAP()


void CommonToolsDlgSM2SignVerify::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();
	unsigned char data_value_key[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	unsigned char data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	editKEYS.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_key, &data_len_key);


	editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_in, &data_len_in);

	if (g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN)
		{
			unsigned int ulRet = OpenSSL_GMECC512SignDigest(
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_key, GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_out, &data_len_out);

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
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_key, SM2_BYTES_LEN,
				(unsigned char *)data_value_out, &data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}

	data_len_tmp = BUFFER_LEN_1K * 4;
	OPF_Bin2Str(data_value_out, data_len_out, (char *)data_value_out_hex, &data_len_out_hex);
	editOUT.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

	OpenSSL_Finalize();
}


void CommonToolsDlgSM2SignVerify::OnBnClickedCancel()
{

	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnCancel();
	unsigned char data_value_key[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;
	unsigned char data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	editKEYS.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_key, &data_len_key);

	OpenSSL_Initialize();

	editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_in, &data_len_in);

	editOUT.GetWindowText(data_value_tmp, data_len_tmp);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), data_value_out, &data_len_out);

	unsigned int ulRet = -1;

	if (g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			ulRet = OpenSSL_GMECC512VerifyDigest(
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_out, data_len_out,
				(unsigned char *)data_value_key, GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_key + GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN
			);
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			ulRet = OpenSSL_SM2VerifyDigest(
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_out, data_len_out,
				(unsigned char *)data_value_key, SM2_BYTES_LEN,
				(unsigned char *)data_value_key + SM2_BYTES_LEN, SM2_BYTES_LEN
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
