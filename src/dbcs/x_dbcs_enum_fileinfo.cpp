
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <smb_qtui.h>
#include <smb_cs.h>

int main(int argc, char * argv[])
{
	SMB_CS_FileInfo_NODE * pHeader = NULL;

	SMB_CS_SetPath("smb_cs.db");
	SMB_CS_Init();

	SMB_CS_EnumFileInfo(&pHeader);

	return 0;
}