﻿// CommonToolsDlgSM2Point.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2Point.h"
#include "afxdialogex.h"
#include "encode_switch.h"
#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"

#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;


// CommonToolsDlgSM2Point ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2Point, CDialogEx)

CommonToolsDlgSM2Point::CommonToolsDlgSM2Point(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2Point::IDD, pParent)
{
	m_iSelXY = -1;
}

CommonToolsDlgSM2Point::~CommonToolsDlgSM2Point()
{
}

void CommonToolsDlgSM2Point::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editXY);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2Point, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2Point::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2Point::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgSM2Point::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgSM2Point::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgSM2Point::OnBnClickedRadio3)
END_MESSAGE_MAP()


// CommonToolsDlgSM2Point ÏûÏ¢´¦Àí³ÌÐò


void CommonToolsDlgSM2Point::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnOK();

	char data_value_xy[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	switch(m_iSelXY)
	{
	case E_INPUT_TYPE_FILE:
		{
			editXY.GetWindowText(file_xy,BUFFER_LEN_1K * 4);

			FILE_READ("", utf8_encode(file_xy).c_str(),(unsigned char *)data_value_xy,&data_len_xy);
		}
		break;
	default:
		{
			editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
			data_len_tmp = wcslen(data_value_tmp);
			OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);
		}
		break;
	}

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		unsigned int ulRet = -1;

		if(data_len_xy == 2* GM_ECC_512_BYTES_LEN)
		{
			ulRet = OpenSSL_GMECC512Point((unsigned char *)data_value_xy,GM_ECC_512_BYTES_LEN,(unsigned char *)data_value_xy + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN);
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
	else
	{
		unsigned int ulRet = -1;

		if(data_len_xy == 2* SM2_BYTES_LEN)
		{
			ulRet = OpenSSL_SM2Point((unsigned char *)data_value_xy,SM2_BYTES_LEN,(unsigned char *)data_value_xy + SM2_BYTES_LEN,SM2_BYTES_LEN);
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

	

}


void CommonToolsDlgSM2Point::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnCancel();
}


void CommonToolsDlgSM2Point::OnBnClickedRadio1()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgSM2Point::OnBnClickedRadio2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgSM2Point::OnBnClickedRadio3()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_HEX;
}