// CommonToolsDlgFILL.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgFILL.h"
#include "afxdialogex.h"
#include "common.h"

// CommonToolsDlgFILL 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgFILL, CDialogEx)

CommonToolsDlgFILL::CommonToolsDlgFILL(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgFILL::IDD, pParent)
{

}

CommonToolsDlgFILL::~CommonToolsDlgFILL()
{
}

void CommonToolsDlgFILL::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editInput);
	DDX_Control(pDX, IDC_EDIT4, editFill);
	DDX_Control(pDX, IDC_EDIT2, editOutput);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgFILL, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgFILL::OnBnClickedOk)
END_MESSAGE_MAP()


// CommonToolsDlgFILL 消息处理程序


void CommonToolsDlgFILL::OnBnClickedOk()
{
	wchar_t data_value_input[BUFFER_LEN_1K * 4];
	wchar_t data_value_fill[BUFFER_LEN_1K * 4];

	wchar_t * data_value_output = NULL;

	int length = 0;
	int pos = 0;
	int i = 0;

	editInput.GetWindowText(data_value_input,BUFFER_LEN_1K * 4);
	editFill.GetWindowText(data_value_fill,BUFFER_LEN_1K * 4);

	length = wcslen(data_value_input) + wcslen(data_value_input)/2 * wcslen(data_value_fill);

	data_value_output = (wchar_t *)malloc(length*2 + 2);

	memset(data_value_output, 0, length*2 + 2);

	pos = 0;

	for(i = 0; i <  wcslen(data_value_input)/2 ; i++)
	{
		memcpy(data_value_output+pos, data_value_fill, wcslen(data_value_fill));
		pos += wcslen(data_value_fill);
		data_value_output[pos] = data_value_input[i*2];
		pos += 1;
		data_value_output[pos] = data_value_input[i*2+1];
		pos += 1;
	}

	editOutput.SetWindowText(data_value_output);

	free(data_value_output);
}
