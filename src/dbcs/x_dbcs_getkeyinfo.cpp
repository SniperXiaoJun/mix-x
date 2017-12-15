
#include <string>
#include <Windows.h>
#include <setupapi.h>
#include <algorithm>
#include <map>

int CollectUSBInfo(int * piCount, char * pVID, char * pPID)
{
	int i = -1;
	int count = 0;
	// ��ȡ��ǰϵͳ����ʹ�õ��豸  
	DWORD dwFlag = (DIGCF_ALLCLASSES | DIGCF_PRESENT);
	HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, dwFlag);
	if (INVALID_HANDLE_VALUE == hDevInfo)
	{
		*piCount = 0;
		return -1;
	}

	// ׼�����������豸����USB  
	SP_DEVINFO_DATA sDevInfoData;
	sDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	std::string strText;
	char szDIS[MAX_PATH]; // Device Identification Strings,   
	DWORD nSize = 0;
	for (int i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &sDevInfoData); i++)
	{
		nSize = 0;
		if (!SetupDiGetDeviceInstanceIdA(hDevInfo, &sDevInfoData, szDIS, sizeof(szDIS), &nSize))
		{
			goto err;
		}

		// �豸ʶ�𴮵�ǰ�����ַ��Ƿ���"USB", ģ�壺 USB\VID_XXXX&PID_XXXX\00000xxxxxxx  
		std::string strDIS(szDIS);

		transform(strDIS.begin(), strDIS.end(), strDIS.begin(), toupper);

		if (strDIS.substr(0, 3) == std::string("USB"))
		{
			if (NULL == pVID || NULL == pPID)
			{
				count++;
			}
			else
			{
				strText += strDIS;
				strText += "\r\n";
				int iVID_Pos = strstr(strDIS.c_str(), pVID) - strDIS.c_str();
				if (iVID_Pos == 8)
				{
					// VID: ���̺�  
					//printf( NIKON_ID  );  
					//printf( "\n");  
					// PID :��Ʒ��  
					int iSlashPos = 0;

					for (const char * p = strDIS.c_str() + strDIS.size(); p > strDIS.c_str(); p--)
					{
						if (*p == '\\')
						{
							iSlashPos = p - strDIS.c_str();
							break;
						}
					}

					int iPID_Pos = strstr(strDIS.c_str(), "PID_") - strDIS.c_str();
					std::string strProductID = strDIS.substr(iPID_Pos + 4, iSlashPos - iPID_Pos - 4);

					if (std::string(pPID) == strProductID)
					{
						count++;
					}

					// ���к�  
					int iRight = strDIS.size() - iSlashPos - 1;
					std::string strSerialNumber = strDIS.substr(iSlashPos + 1, iRight);
				}
			}
		}
	}

	*piCount = count;
err:

	// �ͷ��豸  
	SetupDiDestroyDeviceInfoList(hDevInfo);

	return 0;
}


int main()
{

	//95568�ǹ��ܣ�

	//VID_14D6&PID_1004��
	//VID_14D6&PID_1006��
	//VID_14D6&PID_3002

	//0305X4���ܣ�

	//VID_14D6&PID_3032��һ����
	//VID_14D6&PID_3732������������

	int tmpCount = 0;

	int keyCountHengbaoRSA = 0;
	int keyCountHengbaoSM2 = 0;
	int keyFlag = 0;
	int keyFlagHengbaoRSA = 0;
	int keyFlagHengbaoSM2 = 0;
	int keyFlagOther = 0;

	CollectUSBInfo(&tmpCount, "14D6", "1004");
	keyCountHengbaoRSA += tmpCount;
	CollectUSBInfo(&tmpCount, "14D6", "1006");
	keyCountHengbaoRSA += tmpCount;
	CollectUSBInfo(&tmpCount, "14D6", "3002");
	keyCountHengbaoRSA += tmpCount;

	CollectUSBInfo(&tmpCount, "14D6", "3032");
	keyCountHengbaoSM2 += tmpCount;
	CollectUSBInfo(&tmpCount, "14D6", "3732");
	keyCountHengbaoSM2 += tmpCount;

	if (keyCountHengbaoRSA)
	{
		keyFlag = keyFlag | (1 << 0);
	}

	if (keyCountHengbaoSM2)
	{
		keyFlag = keyFlag | (1 << 1);
	}

	//keyFlag = keyFlag | (1 << 2);

	return keyFlag;
}