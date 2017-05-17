// CommonToolsDlgSM2ENDE.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2ENDE.h"
#include "afxdialogex.h"
#include "encode_switch.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"

#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;


// CommonToolsDlgSM2ENDE ¶Ô»°¿ò

//#define SM2_ENCRYPT_BLOB_SWAP_C2_AND_C3 0

// ½»»»ÃÜÎÄ

// C2 before C3
void sm2_encrypt_blob_swap_c2_before_c3(unsigned char * pbBlob, unsigned int ulBlobLen)
{
#ifdef SM2_ENCRYPT_BLOB_SWAP_C2_AND_C3
	unsigned char * ptr_cpy = (unsigned char *)malloc(ulBlobLen);

	memcpy(ptr_cpy, pbBlob, ulBlobLen);

	// 04 C1 C3 C2 to 04 C1 C2 C3
	memcpy(pbBlob + 1 + 2 * 32, ptr_cpy + 1 + 2 * 32 + 32, ulBlobLen - (1 + 2 * 32 + 32));
	memcpy(pbBlob + ulBlobLen - 32, ptr_cpy + 1 + 2 * 32, 32);

	free(ptr_cpy);
#endif //END SM2_ENCRYPT_BLOB_SWAP_C3_AND_C2
}
// C3 before c2
void sm2_encrypt_blob_swap_c2_after_c3(unsigned char * pbBlob, unsigned int ulBlobLen)
{
#ifdef SM2_ENCRYPT_BLOB_SWAP_C2_AND_C3 
	unsigned char * ptr_cpy = (unsigned char *)malloc(ulBlobLen);

	memcpy(ptr_cpy, pbBlob, ulBlobLen);

	// 04 C1 C2 C3 to 04 C1 C3 C2
	memcpy(pbBlob + 1 + 2 * 32, ptr_cpy + ulBlobLen - 32, 32);
	memcpy(pbBlob + 1 + 2 * 32 + 32, ptr_cpy + 1 + 2 * 32, ulBlobLen - (1 + 2 * 32 + 32));

	free(ptr_cpy);
#endif //END SM2_ENCRYPT_BLOB_SWAP_C3_AND_C2
}






IMPLEMENT_DYNAMIC(CommonToolsDlgSM2ENDE, CDialogEx)

CommonToolsDlgSM2ENDE::CommonToolsDlgSM2ENDE(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2ENDE::IDD, pParent)
{

}

CommonToolsDlgSM2ENDE::~CommonToolsDlgSM2ENDE()
{
}

void CommonToolsDlgSM2ENDE::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT3, editKEYS);
	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT2, editOUT);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2ENDE, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2ENDE::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2ENDE::OnBnClickedCancel)
END_MESSAGE_MAP()

void CommonToolsDlgSM2ENDE::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();
	char data_value_key[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	wchar_t data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t file_in[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t file_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	editKEYS.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

	OPF_WStr2Bin(data_value_tmp, data_len_tmp, (unsigned char *)data_value_key, &data_len_key);


	editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);


	OPF_WStr2Bin(data_value_tmp, data_len_tmp, (unsigned char *)data_value_in, &data_len_in);

	if (g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			unsigned int ulRet = OpenSSL_GMECC512Encrypt((unsigned char *)data_value_key, GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_key + GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_out, &data_len_out);

			sm2_encrypt_blob_swap_c2_after_c3((unsigned char *)data_value_out, data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			unsigned int ulRet = OpenSSL_SM2Encrypt((unsigned char *)data_value_key, SM2_BYTES_LEN,
				(unsigned char *)data_value_key + SM2_BYTES_LEN, SM2_BYTES_LEN,
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_out, &data_len_out);

			sm2_encrypt_blob_swap_c2_after_c3((unsigned char *)data_value_out, data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}


	data_len_tmp = BUFFER_LEN_1K * 4;
	OPF_Bin2WStr(data_value_out, data_len_out, data_value_tmp, &data_len_tmp);
	editOUT.SetWindowText(data_value_tmp);

	OpenSSL_Finalize();
}


void CommonToolsDlgSM2ENDE::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnCancel();
	char data_value_key[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;
	wchar_t data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t file_in[BUFFER_LEN_1K * 4] = { 0 };
	wchar_t file_out[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;

	editKEYS.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);

	OPF_WStr2Bin(data_value_tmp, data_len_tmp, (unsigned char *)data_value_key, &data_len_key);

	OpenSSL_Initialize();


	editIN.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);


	OPF_WStr2Bin(data_value_tmp, data_len_tmp, (unsigned char *)data_value_in, &data_len_in);


	if (g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		sm2_encrypt_blob_swap_c2_before_c3((unsigned char *)data_value_in, data_len_in);

		unsigned int ulRet = OpenSSL_GMECC512Decrypt((const unsigned char *)data_value_key, GM_ECC_512_BYTES_LEN,
			(unsigned char *)data_value_in, data_len_in,
			(unsigned char *)data_value_out, &data_len_out);

		if (ulRet)
		{
			MessageBox(L"操作失败");
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN)
		{

			sm2_encrypt_blob_swap_c2_before_c3((unsigned char *)data_value_in, data_len_in);

			unsigned int ulRet = OpenSSL_SM2Decrypt((const unsigned char *)data_value_key, SM2_BYTES_LEN,
				(unsigned char *)data_value_in, data_len_in,
				(unsigned char *)data_value_out, &data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败");
			}
		}
	}

	data_len_tmp = BUFFER_LEN_1K * 4;
	OPF_Bin2WStr(data_value_out, data_len_out, data_value_tmp, &data_len_tmp);
	editOUT.SetWindowText(data_value_tmp);

	OpenSSL_Finalize();
}
