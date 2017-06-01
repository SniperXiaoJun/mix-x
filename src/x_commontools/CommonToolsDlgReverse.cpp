// CommonToolsDlgReverse.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgReverse.h"
#include "afxdialogex.h"
#include "common.h"
#include "o_all_func_def.h"
#include "encode_switch.h"
// CommonToolsDlgReverse 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgReverse, CDialogEx)

CommonToolsDlgReverse::CommonToolsDlgReverse(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgReverse::IDD, pParent)
{

}

CommonToolsDlgReverse::~CommonToolsDlgReverse()
{
}

void CommonToolsDlgReverse::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editInput);
	DDX_Control(pDX, IDC_EDIT4, editBitLen);
	DDX_Control(pDX, IDC_EDIT2, editOutput);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgReverse, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgReverse::OnBnClickedOk)
END_MESSAGE_MAP()


// CommonToolsDlgReverse 消息处理程序


void CommonToolsDlgReverse::OnBnClickedOk()
{
	unsigned char data_value_input[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_output[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_input = BUFFER_LEN_1K * 4;
	unsigned int data_len_output = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;

	int length = 0;
	int pos = 0;
	int i = 0;
	int bitlen = 0;
	int realbitlen = 1;


	editInput.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()), (unsigned char *)data_value_input,&data_len_input);

	editBitLen.GetWindowText(data_value_tmp, BUFFER_LEN_1K * 4);
	bitlen = atoi((char *)utf8_encode(data_value_tmp).c_str());

	while(bitlen > realbitlen)
	{
		if (bitlen == realbitlen)
		{
			break;
		}

		realbitlen *= 2;
	}

	bitlen = realbitlen;

	if (8 <= bitlen)
	{
		for(i = 0; i < data_len_input;)
		{
			memcpy(data_value_output + (data_len_input - i-bitlen/8), data_value_input+i, bitlen/8);
			i +=  bitlen/8;
		}
	}
	else if(4 == bitlen)
	{
		for(i = 0; i < data_len_input;i++)
		{
			unsigned char c_char[2];

			unsigned char c_char_all;

			c_char[0] = (data_value_input[i]>>0) & 0x0F;
			c_char[1] = (data_value_input[i]>>4) & 0x0F;

			c_char_all = (c_char[0]<<4) +  (c_char[1]<<0);

			data_value_output[data_len_input - i -1] = c_char_all;
		}
	}
	else if(2 == bitlen)
	{
		for(i = 0; i < data_len_input;i++)
		{
			unsigned char c_char[4];

			unsigned char c_char_all;

			c_char[0] = (data_value_input[i]>>0) & 0x03;
			c_char[1] = (data_value_input[i]>>2) & 0x03;
			c_char[2] = (data_value_input[i]>>4) & 0x03;
			c_char[3] = (data_value_input[i]>>6) & 0x03;

			c_char_all = (c_char[0]<<6) +  (c_char[1]<<4) + (c_char[2]<<2) +  (c_char[3]<<0);

			data_value_output[data_len_input - i -1] = c_char_all;
		}
	}
	else if(1 == bitlen)
	{
		for(i = 0; i < data_len_input;i++)
		{
			unsigned char c_char[8];

			unsigned char c_char_all;

			c_char[0] = data_value_input[i]>>0 & 0x01;
			c_char[1] = data_value_input[i]>>1 & 0x01;
			c_char[2] = data_value_input[i]>>2 & 0x01;
			c_char[3] = data_value_input[i]>>3 & 0x01;
			c_char[4] = data_value_input[i]>>4 & 0x01;
			c_char[5] = data_value_input[i]>>5 & 0x01;
			c_char[6] = data_value_input[i]>>6 & 0x01;
			c_char[7] = data_value_input[i]>>7 & 0x01;

			c_char_all = (c_char[0]<<7) +  (c_char[1]<<6) + (c_char[2]<<5) +  (c_char[3]<<4)
				+(c_char[4]<<3) +  (c_char[5]<<2) + (c_char[6]<<1) +  (c_char[7]<<0);

			data_value_output[data_len_input - i -1] = c_char_all;
		}
	}

	data_len_output = data_len_input;

	data_len_tmp = BUFFER_LEN_1K *4;
	OPF_Bin2Str( (unsigned char *)data_value_output,data_len_output, (char *)data_value_out_hex, &data_len_out_hex);

	editOutput.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());
}


BOOL CommonToolsDlgReverse::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	editBitLen.SetWindowText(L"8");

	return TRUE;  
}
