
#include <smb_cs.h>
#include <smb_dev.h>
#include "json/json.h"
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>

using namespace std;

void filesearch(string path, int layer)
{
	struct _finddata_t filefind;

	string curr = path + "\\*.*";

	int done = 0, i, handle;

	if ((handle = _findfirst(curr.c_str(), &filefind)) == -1)return;

	while (!(done = _findnext(handle, &filefind)))
	{
		if (!strcmp(filefind.name, ".."))continue;

		for (i = 0; i<layer; i++)cout << " ";

		curr = path + "\\" + filefind.name;

		if ((_A_SUBDIR == filefind.attrib))
		{
			cout << filefind.name << "(dir)" << endl;

			filesearch(curr, layer + 1);
		}
		else
		{
			cout << filefind.name << endl;
			
			std::fstream _file;

			_file.open(curr, ios::binary | ios::in);

			if (_file)
			{
				std::ios::pos_type length;
				unsigned int ulAlgType = 0;
				unsigned char pbCaCert[1024 * 4] = { 0 };

				// get length of file:
				_file.seekg(0, ios::end);
				length = _file.tellg();
				_file.seekg(0, ios::beg);

				// read data as a block:
				_file.read((char *)pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length);
				_file.close();

				SMB_CS_ImportCaCert(pbCaCert, length>sizeof(pbCaCert) ? sizeof(pbCaCert) : length, &ulAlgType);
			}
			else
			{

			}

		}
	}

	_findclose(handle);
}

#if defined(WIN32) || defined(WINDOWS)
#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"")
#else

#endif


int main(int argc, char * argv[])
{
	SMB_CS_SetPath("smb_cs.db");
	SMB_CS_Init();

	SMB_CS_CertificateContext_NODE *header = NULL;
	
	SMB_CS_EnumCertCtx(&header, 0);

	SMB_CS_DelCertCtxLink(header);

	std::string path = ".";

	filesearch(path, 1);

	return 0;
}