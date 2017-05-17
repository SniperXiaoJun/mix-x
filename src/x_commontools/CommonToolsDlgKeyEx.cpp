// CommonToolsDlgKeyEx.cpp : implementation file
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgKeyEx.h"
#include "afxdialogex.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "gm-hash-bit.h"
#include "gm-ecc-512.h"
#include "sm2.h"
#include "encode_switch.h"

extern E_KEY_ALG_TYPE g_KeyAlgType;





// CommonToolsDlgKeyEx dialog

IMPLEMENT_DYNAMIC(CommonToolsDlgKeyEx, CDialogEx)

CommonToolsDlgKeyEx::CommonToolsDlgKeyEx(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgKeyEx::IDD, pParent)
{

}

CommonToolsDlgKeyEx::~CommonToolsDlgKeyEx()
{
}

void CommonToolsDlgKeyEx::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, m_editprv);
	DDX_Control(pDX, IDC_EDIT2, m_editpub);
	DDX_Control(pDX, IDC_EDIT8, m_editprvar);
	DDX_Control(pDX, IDC_EDIT9, m_editpubar);
	DDX_Control(pDX, IDC_EDIT10, m_editpubb);
	DDX_Control(pDX, IDC_EDIT11, m_editpubbr);
	DDX_Control(pDX, IDC_EDIT12, m_editida);
	DDX_Control(pDX, IDC_EDIT13, m_editidb);
	DDX_Control(pDX, IDC_EDIT14, m_editkey_len);
	DDX_Control(pDX, IDC_EDIT15, m_editkey);
	DDX_Control(pDX, IDC_EDIT16, m_editS1);
	DDX_Control(pDX, IDC_EDIT17, m_editSA);


	DDX_Control(pDX, IDC_COMBO1, m_comboA);




	int pos = -1;

	pos = m_comboA.InsertString(pos + 1, L"是");
	pos = m_comboA.InsertString(pos + 1, L"否");

	m_comboA.SetCurSel(0);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgKeyEx, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgKeyEx::OnBnClickedCancel)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CommonToolsDlgKeyEx::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()


// CommonToolsDlgKeyEx message handlers


void CommonToolsDlgKeyEx::OnBnClickedCancel()
{

	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnOK();
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};

	unsigned char data_value_key[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;

	unsigned char data_value_S1[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_S1 = 32;

	unsigned char data_value_SA[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_SA = 32;

	unsigned char data_value_xy_A[BUFFER_LEN_1K * 4] = {0x04};
	unsigned int data_len_xy_A = BUFFER_LEN_1K * 4;

	unsigned char data_value_prv_A[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_prv_A = BUFFER_LEN_1K * 4;


	unsigned char data_value_xy_AR[BUFFER_LEN_1K * 4] = {0x04};
	unsigned int data_len_xy_AR = BUFFER_LEN_1K * 4;

	unsigned char data_value_prv_AR[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_prv_AR = BUFFER_LEN_1K * 4;


	unsigned char data_value_xy_B[BUFFER_LEN_1K * 4] = {0x04};
	unsigned int data_len_xy_B = BUFFER_LEN_1K * 4;


	unsigned char data_value_xy_BR[BUFFER_LEN_1K * 4] = {0x04};
	unsigned int data_len_xy_BR = BUFFER_LEN_1K * 4;

	unsigned char data_value_key_len[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key_len = BUFFER_LEN_1K * 4;

	int key_len = 0;

	unsigned char data_value_ida[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_ida = BUFFER_LEN_1K * 4;

	unsigned char data_value_idb[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_idb = BUFFER_LEN_1K * 4;

	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;


	unsigned int ulRet = 0;

	OpenSSL_Initialize();

	//ida
	m_editida.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_ida,&data_len_ida);
	//idb
	m_editidb.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);	
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_idb,&data_len_idb);

	//prv
	m_editprv.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_prv_A,&data_len_prv_A);

	//prvar
	m_editprvar.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_prv_AR,&data_len_prv_AR);

	//pub
	m_editpub.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_xy_A+1,&data_len_xy_A);

	//pubar
	m_editpubar.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_xy_AR+1,&data_len_xy_AR);

	//pubb
	
	m_editpubb.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_xy_B+1,&data_len_xy_B);

	//pubbr
	
	m_editpubbr.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()),data_value_xy_BR+1,&data_len_xy_BR);

	//key_len
	
	m_editkey_len.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	key_len = atoi((char *)utf8_encode(data_value_tmp).c_str());

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		unsigned char ZA[64] = {0};
		unsigned char ZB[64] = {0};


		tcm_gmecc512_get_usrinfo_value(data_value_ida,data_len_ida,data_value_xy_A,data_len_xy_A+1,ZA, EHASH_TYPE_ZY_HASH_256);
		tcm_gmecc512_get_usrinfo_value(data_value_idb,data_len_idb,data_value_xy_B,data_len_xy_B+1,ZB, EHASH_TYPE_ZY_HASH_256);

		ulRet = tcm_gmecc512_exchange(m_comboA.GetCurSel() == 0,
			data_value_prv_A,data_value_xy_A,
			data_value_prv_AR,data_value_xy_AR,
			data_value_xy_B,data_value_xy_BR,
			ZA,ZB,
			data_value_key,data_value_S1,data_value_SA,key_len);

		data_len_key_len = key_len;

	}
	else
	{
		unsigned char ZA[32] = {0};
		unsigned char ZB[32] = {0};


		tcm_get_usrinfo_value(data_value_ida,data_len_ida,data_value_xy_A,data_len_xy_A+1,ZA);
		tcm_get_usrinfo_value(data_value_idb,data_len_idb,data_value_xy_B,data_len_xy_B+1,ZB);

		ulRet = tcm_ecc_exchange(m_comboA.GetCurSel() == 0,
			data_value_prv_A,data_value_xy_A,
			data_value_prv_AR,data_value_xy_AR,
			data_value_xy_B,data_value_xy_BR,
			ZA,ZB,
			data_value_key,data_value_S1,data_value_SA);

		data_len_key_len = 16;
	}

	OpenSSL_Finalize();

	if (0 == ulRet)
	{
		data_len_out_hex = BUFFER_LEN_1K * 4;
		OPF_Bin2Str(data_value_key,data_len_key_len, (char *)data_value_out_hex,&data_len_out_hex);
		m_editkey.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

		data_len_out_hex = BUFFER_LEN_1K * 4;
		OPF_Bin2Str(data_value_S1,data_len_S1, (char *)data_value_out_hex, &data_len_out_hex);
		m_editS1.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

		data_len_out_hex = BUFFER_LEN_1K * 4;
		OPF_Bin2Str(data_value_SA,data_len_SA, (char *)data_value_out_hex, &data_len_out_hex);
		m_editSA.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());
	}
	else
	{
		MessageBox(L"操作失败");
	}


}


void CommonToolsDlgKeyEx::OnCbnSelchangeCombo1()
{
	// TODO: Add your control notification handler code here
}
