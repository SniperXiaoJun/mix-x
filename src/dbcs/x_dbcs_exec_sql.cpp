
#include <smb_cs.h>
#include <iostream>
#include <fstream>
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

			if (strstr(filefind.name, ".sql"))
			{
				_file.open(curr, ios::binary | ios::in);

				if (_file)
				{
					std::ios::pos_type length;
					unsigned int ulAlgType = 0;
					char * pbSqlData = NULL;
					int pos = 0;

					// get length of file:
					_file.seekg(0, ios::end);
					length = _file.tellg();
					_file.seekg(0, ios::beg);

					pbSqlData = new char[length];

					// read data as a block:
					_file.read(pbSqlData+ pos, length);

					SMB_CS_ExecSQL(pbSqlData, length);

					delete []pbSqlData;

					_file.close();
				}
				else
				{

				}
			}
			else
			{

			}
			

		}
	}

	_findclose(handle);
}

int main()
{
	SMB_DB_Path_Init("smb_cs.db");
	SMB_DB_Init();

	filesearch(".", 1);

	return 0;
}