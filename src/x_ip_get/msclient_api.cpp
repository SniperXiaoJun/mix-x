
#include "msclient_api.h"
#include <stdio.h>
#include <string>
#include <iostream> 
#include <sstream>
#include <fstream>


#include "registry.h"
#include "iphlpapi.h"

#pragma comment(lib,"iphlpapi.lib") 
#pragma comment(lib, "version.lib")
using namespace std;  
using namespace base;

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

#define CHAR_TO_16(achar) ((achar)>='0'&&(achar)<='9'?((achar)-'0'):((((((achar)>='A'  )&&( (achar)<='Z' )  ))? ((achar)-'A'): ((achar)-'a')) + 10))


#define  FILE_DEVICE_SCSI              0x0000001b
#define  IOCTL_SCSI_MINIPORT_IDENTIFY  ( ( FILE_DEVICE_SCSI << 16 ) + 0x0501 )

#define  IOCTL_SCSI_MINIPORT 0x0004D008  //  see NTDDSCSI.H for definition

#define  IDENTIFY_BUFFER_SIZE  512
#define  SENDIDLENGTH  ( sizeof( SENDCMDOUTPARAMS ) + IDENTIFY_BUFFER_SIZE )

#define  IDE_ATAPI_IDENTIFY  0xA1  //  Returns ID sector for ATAPI.
#define  IDE_ATA_IDENTIFY    0xEC  //  Returns ID sector for ATA.
#define  DFP_RECEIVE_DRIVE_DATA   0x0007c088

typedef struct _IDSECTOR
{
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique[3];
	CHAR    sSerialNumber[20];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev[8];
	CHAR    sModelNumber[40];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bReserved[128];
} IDSECTOR, *PIDSECTOR;

//typedef struct _DRIVERSTATUS
//{
//	BYTE  bDriverError;  //  Error code from driver, or 0 if no error.
//	BYTE  bIDEStatus;    //  Contents of IDE Error register.
//	//  Only valid when bDriverError is SMART_IDE_ERROR.
//	BYTE  bReserved[2];  //  Reserved for future expansion.
//	DWORD  dwReserved[2];  //  Reserved for future expansion.
//} DRIVERSTATUS, *PDRIVERSTATUS, *LPDRIVERSTATUS;

//typedef struct _SENDCMDOUTPARAMS
//{
//	DWORD         cBufferSize;   //  Size of bBuffer in bytes
//	DRIVERSTATUS  DriverStatus;  //  Driver status structure.
//	BYTE          bBuffer[1];    //  Buffer of arbitrary length in which to store the data read from the                                                       // drive.
//} SENDCMDOUTPARAMS, *PSENDCMDOUTPARAMS, *LPSENDCMDOUTPARAMS;

typedef struct _SRB_IO_CONTROL
{
	ULONG HeaderLength;
	UCHAR Signature[8];
	ULONG Timeout;
	ULONG ControlCode;
	ULONG ReturnCode;
	ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;

//typedef struct _IDEREGS
//{
//	BYTE bFeaturesReg;       // Used for specifying SMART "commands".
//	BYTE bSectorCountReg;    // IDE sector count register
//	BYTE bSectorNumberReg;   // IDE sector number register
//	BYTE bCylLowReg;         // IDE low order cylinder value
//	BYTE bCylHighReg;        // IDE high order cylinder value
//	BYTE bDriveHeadReg;      // IDE drive/head register
//	BYTE bCommandReg;        // Actual IDE command.
//	BYTE bReserved;          // reserved for future use.  Must be zero.
//} IDEREGS, *PIDEREGS, *LPIDEREGS;

//typedef struct _SENDCMDINPARAMS
//{
//	DWORD     cBufferSize;   //  Buffer size in bytes
//	IDEREGS   irDriveRegs;   //  Structure with drive register values.
//	BYTE bDriveNumber;       //  Physical drive number to send 
//	//  command to (0,1,2,3).
//	BYTE bReserved[3];       //  Reserved for future expansion.
//	DWORD     dwReserved[4]; //  For future use.
//	BYTE      bBuffer[1];    //  Input buffer.
//} SENDCMDINPARAMS, *PSENDCMDINPARAMS, *LPSENDCMDINPARAMS;

typedef struct _GETVERSIONOUTPARAMS
{
	BYTE bVersion;      // Binary driver version.
	BYTE bRevision;     // Binary driver revision.
	BYTE bReserved;     // Not used.
	BYTE bIDEDeviceMap; // Bit map of IDE devices.
	DWORD fCapabilities; // Bit mask of driver capabilities.
	DWORD dwReserved[4]; // For future use.
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

//////////////////////////////////////////////////////////////////////

//结构定义 
typedef struct _UNICODE_STRING 
{ 
	USHORT  Length;//长度 
	USHORT  MaximumLength;//最大长度 
	PWSTR  Buffer;//缓存指针 
} UNICODE_STRING,*PUNICODE_STRING; 

typedef struct _OBJECT_ATTRIBUTES 
{ 
	ULONG Length;//长度 18h 
	HANDLE RootDirectory;//  00000000 
	PUNICODE_STRING ObjectName;//指向对象名的指针 
	ULONG Attributes;//对象属性00000040h 
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR，0 
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE，0 
} OBJECT_ATTRIBUTES; 
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES; 

//函数指针变量类型
typedef DWORD  (__stdcall *ZWOS )( PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES); 
typedef DWORD  (__stdcall *ZWMV )( HANDLE,HANDLE,PVOID,ULONG,ULONG,PLARGE_INTEGER,PSIZE_T,DWORD,ULONG,ULONG); 
typedef DWORD  (__stdcall *ZWUMV )( HANDLE,PVOID); 

std::vector<std::wstring> &split(const std::wstring &s, wchar_t delim, std::vector<std::wstring> &elems) {
	std::wstringstream ss(s);
	std::wstring item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}


std::vector<std::wstring> split(const std::wstring &s, wchar_t delim) {
	std::vector<std::wstring> elems;
	split(s, delim, elems);
	return elems;
}

// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring &wstr){
	// when got a empty wstring, vs2010 will break on an asserting: string 
	// substring out of range
	if (wstr.size()==0) return "";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo( size_needed, 0 );
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring utf8_decode(const std::string &str){
	if (str.size()==0) return L"";
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo( size_needed, 0 );
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}

unsigned int OPF_Str2Bin(const char *pbIN,unsigned int uiINLen,unsigned char *pbOUT,unsigned int * puiOUTLen)
{
	int i;
	unsigned int sn_len = uiINLen / 2;

	if(sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		return -1;
	}

	*puiOUTLen = sn_len;

	if(0 == pbOUT)
	{

	}
	else
	{
		memset(pbOUT, 0,sn_len);
		for (i = 0; i < sn_len; i++) {
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2)) * 16;
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2 + 1));
		}
	}

	return 0;
}

unsigned int OPF_Bin2Str(const unsigned char *pbIN,unsigned int uiINLen,char *pbOUT,unsigned int * puiOUTLen)
{
	int i;
	unsigned int sn_len = uiINLen * 2;

	if(sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		return -1;
	}

	*puiOUTLen = sn_len;

	if(0 == pbOUT)
	{

	}
	else
	{
		for (i = 0; i < uiINLen; i++) {
			sprintf(pbOUT + 2 * i, "%02X", pbIN[i]);
		}
	}

	return 0;
}

BOOL WinNTHDSerialNumAsScsiRead( BYTE* dwSerial, UINT* puSerialLen, UINT uMaxSerialLen )
{
	BOOL bInfoLoaded = FALSE;

	for( int iController = 0; iController < 4; ++ iController )
	{
		HANDLE hScsiDriveIOCTL = 0;
		char   szDriveName[256];

		//  Try to get a handle to PhysicalDrive IOCTL, report failure
		//  and exit if can't.
		sprintf( szDriveName, "\\\\.\\Scsi%d:", iController );

		//  Windows NT, Windows 2000, any rights should do
		hScsiDriveIOCTL = CreateFile( szDriveName,
			GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		// if (hScsiDriveIOCTL == INVALID_HANDLE_VALUE)
		//    printf ("Unable to open SCSI controller %d, error code: 0x%lX\n",
		//            controller, GetLastError ());

		if( hScsiDriveIOCTL != INVALID_HANDLE_VALUE )
		{
			int iDrive = 0;
			for( iDrive = 0; iDrive < 16; ++ iDrive )
			{
				char szBuffer[sizeof( SRB_IO_CONTROL ) + SENDIDLENGTH] = { 0 };

				SRB_IO_CONTROL* p = ( SRB_IO_CONTROL* )szBuffer;
				SENDCMDINPARAMS* pin = ( SENDCMDINPARAMS* )( szBuffer + sizeof( SRB_IO_CONTROL ) );
				DWORD dwResult;

				p->HeaderLength = sizeof( SRB_IO_CONTROL );
				p->Timeout = 10000;
				p->Length = SENDIDLENGTH;
				p->ControlCode = IOCTL_SCSI_MINIPORT_IDENTIFY;
				strncpy( ( char* )p->Signature, "SCSIDISK", 8 );

				pin->irDriveRegs.bCommandReg = IDE_ATA_IDENTIFY;
				pin->bDriveNumber = iDrive;

				if( DeviceIoControl( hScsiDriveIOCTL, IOCTL_SCSI_MINIPORT, 
					szBuffer,
					sizeof( SRB_IO_CONTROL ) + sizeof( SENDCMDINPARAMS ) - 1,
					szBuffer,
					sizeof( SRB_IO_CONTROL ) + SENDIDLENGTH,
					&dwResult, NULL ) )
				{
					SENDCMDOUTPARAMS* pOut = ( SENDCMDOUTPARAMS* )( szBuffer + sizeof( SRB_IO_CONTROL ) );
					IDSECTOR* pId = ( IDSECTOR* )( pOut->bBuffer );
					if( pId->sModelNumber[0] )
					{
						if( * puSerialLen + 20U <= uMaxSerialLen )
						{
							UINT i;
							// 序列号
							CopyMemory( dwSerial + * puSerialLen, ( ( USHORT* )pId ) + 10, 20 );

							// Cut off the trailing blanks
							for( i = 20; i != 0U && ' ' == dwSerial[* puSerialLen + i - 1]; -- i )
							{}
							* puSerialLen += i;

							// 型号
							CopyMemory( dwSerial + * puSerialLen, ( ( USHORT* )pId ) + 27, 40 );
							// Cut off the trailing blanks
							for( i = 40; i != 0U && ' ' == dwSerial[* puSerialLen + i - 1]; -- i )
							{}
							* puSerialLen += i;

							bInfoLoaded = TRUE;
						}
						else
						{
							::CloseHandle( hScsiDriveIOCTL );
							return bInfoLoaded;
						}
					}
				}
			}
			::CloseHandle( hScsiDriveIOCTL );
		}
	}
	return bInfoLoaded;
}

BOOL DoIdentify( HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP,
	PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd, BYTE bDriveNum,
	PDWORD lpcbBytesReturned )
{
	// Set up data structures for IDENTIFY command.
	pSCIP->cBufferSize                  = IDENTIFY_BUFFER_SIZE;
	pSCIP->irDriveRegs.bFeaturesReg     = 0;
	pSCIP->irDriveRegs.bSectorCountReg  = 1;
	pSCIP->irDriveRegs.bSectorNumberReg = 1;
	pSCIP->irDriveRegs.bCylLowReg       = 0;
	pSCIP->irDriveRegs.bCylHighReg      = 0;

	// calc the drive number.
	pSCIP->irDriveRegs.bDriveHeadReg = 0xA0 | ( ( bDriveNum & 1 ) << 4 );

	// The command can either be IDE identify or ATAPI identify.
	pSCIP->irDriveRegs.bCommandReg = bIDCmd;
	pSCIP->bDriveNumber = bDriveNum;
	pSCIP->cBufferSize = IDENTIFY_BUFFER_SIZE;

	return DeviceIoControl( hPhysicalDriveIOCTL, DFP_RECEIVE_DRIVE_DATA,
		( LPVOID ) pSCIP,
		sizeof( SENDCMDINPARAMS ) - 1,
		( LPVOID ) pSCOP,
		sizeof( SENDCMDOUTPARAMS ) + IDENTIFY_BUFFER_SIZE - 1,
		lpcbBytesReturned, NULL );
}

BOOL WinNTHDSerialNumAsPhysicalRead( BYTE* dwSerial, UINT* puSerialLen, UINT uMaxSerialLen )
{
#define  DFP_GET_VERSION          0x00074080
	BOOL bInfoLoaded = FALSE;

	for( UINT uDrive = 0; uDrive < 4; ++ uDrive )
	{
		HANDLE hPhysicalDriveIOCTL = 0;

		//  Try to get a handle to PhysicalDrive IOCTL, report failure
		//  and exit if can't.
		char szDriveName [256];
		sprintf( szDriveName, "\\\\.\\PhysicalDrive%d", uDrive );

		//  Windows NT, Windows 2000, must have admin rights
		hPhysicalDriveIOCTL = CreateFile( szDriveName,
			GENERIC_READ | GENERIC_WRITE, 
			FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
			OPEN_EXISTING, 0, NULL);

		if( hPhysicalDriveIOCTL != INVALID_HANDLE_VALUE )
		{
			GETVERSIONOUTPARAMS VersionParams = { 0 };
			DWORD               cbBytesReturned = 0;

			// Get the version, etc of PhysicalDrive IOCTL
			if( DeviceIoControl( hPhysicalDriveIOCTL, DFP_GET_VERSION,
				NULL, 
				0,
				&VersionParams,
				sizeof( GETVERSIONOUTPARAMS ),
				&cbBytesReturned, NULL ) )
			{
				// If there is a IDE device at number "i" issue commands
				// to the device
				if( VersionParams.bIDEDeviceMap != 0 )
				{
					BYTE             bIDCmd = 0;   // IDE or ATAPI IDENTIFY cmd
					SENDCMDINPARAMS  scip = { 0 };

					// Now, get the ID sector for all IDE devices in the system.
					// If the device is ATAPI use the IDE_ATAPI_IDENTIFY command,
					// otherwise use the IDE_ATA_IDENTIFY command
					bIDCmd = ( VersionParams.bIDEDeviceMap >> uDrive & 0x10 ) ? IDE_ATAPI_IDENTIFY : IDE_ATA_IDENTIFY;
					BYTE IdOutCmd[sizeof( SENDCMDOUTPARAMS ) + IDENTIFY_BUFFER_SIZE - 1] = { 0 };

					if( DoIdentify( hPhysicalDriveIOCTL, 
						&scip, 
						( PSENDCMDOUTPARAMS )&IdOutCmd, 
						( BYTE )bIDCmd,
						( BYTE )uDrive,
						&cbBytesReturned ) )
					{
						if( * puSerialLen + 20U <= uMaxSerialLen )
						{
							UINT i;

							CopyMemory( dwSerial + * puSerialLen, ( ( USHORT* )( ( ( PSENDCMDOUTPARAMS )IdOutCmd )->bBuffer ) ) + 10, 20 );  // 序列号

							// Cut off the trailing blanks
							for( i = 20; i != 0U && ' ' == dwSerial[* puSerialLen + i - 1]; -- i )  {}
							* puSerialLen += i;

							CopyMemory( dwSerial + * puSerialLen, ( ( USHORT* )( ( ( PSENDCMDOUTPARAMS )IdOutCmd )->bBuffer ) ) + 27, 40 ); // 型号

							// Cut off the trailing blanks
							for( i = 40; i != 0U && ' ' == dwSerial[* puSerialLen + i - 1]; -- i )  {}
							* puSerialLen += i;

							bInfoLoaded = TRUE;
						}
						else
						{
							::CloseHandle( hPhysicalDriveIOCTL );
							return bInfoLoaded;
						}
					}
				}
			}
			CloseHandle( hPhysicalDriveIOCTL );
		}
	}
	return bInfoLoaded;
}

UINT FindAwardBios( BYTE** ppBiosAddr )
{
	BYTE* pBiosAddr = * ppBiosAddr + 0xEC71;

	BYTE szBiosData[128];
	CopyMemory( szBiosData, pBiosAddr, 127 );
	szBiosData[127] = 0;

	int iLen = lstrlen( ( char* )szBiosData );
	if( iLen > 0 && iLen < 128 )
	{
		//AWard:         07/08/2002-i845G-ITE8712-JF69VD0CC-00 
		//Phoenix-Award: 03/12/2002-sis645-p4s333
		if( szBiosData[2] == '/' && szBiosData[5] == '/' )
		{
			BYTE* p = szBiosData;
			while( * p )
			{
				if( * p < ' ' || * p >= 127 )
				{
					break;
				}
				++ p;
			}
			if( * p == 0 )
			{
				* ppBiosAddr = pBiosAddr;
				return ( UINT )iLen;
			}
		}
	}
	return 0;
}

UINT FindAmiBios( BYTE** ppBiosAddr )
{
	BYTE* pBiosAddr = * ppBiosAddr + 0xF478;

	BYTE szBiosData[128];
	CopyMemory( szBiosData, pBiosAddr, 127 );
	szBiosData[127] = 0;

	int iLen = lstrlen( ( char* )szBiosData );
	if( iLen > 0 && iLen < 128 )
	{
		// Example: "AMI: 51-2300-000000-00101111-030199-"
		if( szBiosData[2] == '-' && szBiosData[7] == '-' )
		{
			BYTE* p = szBiosData;
			while( * p )
			{
				if( * p < ' ' || * p >= 127 )
				{
					break;
				}
				++ p;
			}
			if( * p == 0 )
			{
				* ppBiosAddr = pBiosAddr;
				return ( UINT )iLen;
			}
		}
	}
	return 0;
}

UINT FindPhoenixBios( BYTE** ppBiosAddr )
{
	UINT uOffset[3] = { 0x6577, 0x7196, 0x7550 };
	for( UINT i = 0; i < 3; ++ i )
	{
		BYTE* pBiosAddr = * ppBiosAddr + uOffset[i];

		BYTE szBiosData[128];
		CopyMemory( szBiosData, pBiosAddr, 127 );
		szBiosData[127] = 0;

		int iLen = lstrlen( ( char* )szBiosData );
		if( iLen > 0 && iLen < 128 )
		{
			// Example: Phoenix "NITELT0.86B.0044.P11.9910111055"
			if( szBiosData[7] == '.' && szBiosData[11] == '.' )
			{
				BYTE* p = szBiosData;
				while( * p )
				{
					if( * p < ' ' || * p >= 127 )
					{
						break;
					}
					++ p;
				}
				if( * p == 0 )
				{
					* ppBiosAddr = pBiosAddr;
					return ( UINT )iLen;
				}
			}
		}
	}
	return 0;
}


/////////////////////////////////
BYTE szSystemInfo[4096]; // 在程序执行完毕后，此处存储取得的系统特征码
UINT uSystemInfoLen = 0; // 在程序执行完毕后，此处存储取得的系统特征码的长度


// BIOS 编号，支持 AMI, AWARD, PHOENIX
BOOL GetBiosSn()
{
	BOOL ret = FALSE;

	SIZE_T ssize; 

	LARGE_INTEGER so; 
	so.LowPart=0x000f0000;
	so.HighPart=0x00000000; 
	ssize=0xffff; 
	wchar_t strPH[30]=L"\\device\\physicalmemory"; 

	DWORD ba=0;

	UNICODE_STRING struniph; 
	struniph.Buffer=strPH; 
	struniph.Length=0x2c; 
	struniph.MaximumLength =0x2e; 

	OBJECT_ATTRIBUTES obj_ar; 
	obj_ar.Attributes =64;
	obj_ar.Length =24;
	obj_ar.ObjectName=&struniph;
	obj_ar.RootDirectory=0; 
	obj_ar.SecurityDescriptor=0; 
	obj_ar.SecurityQualityOfService =0; 

	HMODULE hinstLib = LoadLibrary("ntdll.dll"); 
	ZWOS ZWopenS=(ZWOS)GetProcAddress(hinstLib,"ZwOpenSection"); 
	ZWMV ZWmapV=(ZWMV)GetProcAddress(hinstLib,"ZwMapViewOfSection"); 
	ZWUMV ZWunmapV=(ZWUMV)GetProcAddress(hinstLib,"ZwUnmapViewOfSection"); 

	//调用函数，对物理内存进行映射 
	HANDLE hSection; 
	if( 0 == ZWopenS(&hSection,4,&obj_ar) && 
		0 == ZWmapV( 
		( HANDLE )hSection,   //打开Section时得到的句柄 
		( HANDLE )0xFFFFFFFF, //将要映射进程的句柄， 
		&ba,                  //映射的基址 
		0,
		0xFFFF,               //分配的大小 
		&so,                  //物理内存的地址 
		&ssize,               //指向读取内存块大小的指针 
		1,                    //子进程的可继承性设定 
		0,                    //分配类型 
		2                     //保护类型 
		) )
		//执行后会在当前进程的空间开辟一段64k的空间，并把f000:0000到f000:ffff处的内容映射到这里 
		//映射的基址由ba返回,如果映射不再有用,应该用ZwUnmapViewOfSection断开映射 
	{
		BYTE* pBiosSerial = ( BYTE* )ba;
		UINT uBiosSerialLen = FindAwardBios( &pBiosSerial );
		if( uBiosSerialLen == 0U )
		{
			uBiosSerialLen = FindAmiBios( &pBiosSerial );
			if( uBiosSerialLen == 0U )
			{
				uBiosSerialLen = FindPhoenixBios( &pBiosSerial );
			}
		}

		if( uBiosSerialLen != 0U )
		{
			CopyMemory( szSystemInfo + uSystemInfoLen, pBiosSerial, uBiosSerialLen );
			uSystemInfoLen += uBiosSerialLen;

			ret = TRUE;
		}

		ZWunmapV( ( HANDLE )0xFFFFFFFF, ( void* )ba );
	}

	return ret;
}




unsigned int MSCAPI_ConnectSecureElement(int iFlag)
{
	return 0;
}


unsigned int MSCAPI_DisConnectSecureElement(int iFlag)
{
	return 0;
}


unsigned int MSCAPI_ReadSecureElementSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag)
{
	return 0;
}



unsigned int MSCAPI_ReadSecureElementCerts(char * pszCerts,unsigned int *puiCertsLen, int iFlag)
{
	return 0;
}



unsigned int MSCAPI_ReadCPUSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag)
{
	BOOL bException = FALSE;
	BYTE szCpu[16]  = { 0 };
	UINT uCpuID     = 0U;
	int rv = MSCAPIErrCodeSuccess;
	BYTE szSystemInfo[BUFFER_LEN_1K] = {0}; // 在程序执行完毕后，此处存储取得的系统特征码
	UINT uSystemInfoLen = 0; // 在程序执行完毕后，此处存储取得的系统特征码的长度

	__try 
	{
		_asm 
		{
			mov eax, 0
				cpuid
				mov dword ptr szCpu[0], ebx
				mov dword ptr szCpu[4], edx
				mov dword ptr szCpu[8], ecx
				mov eax, 1
				cpuid
				mov uCpuID, edx
		}
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		bException = TRUE;
	}

	if( !bException )
	{
		CopyMemory( szSystemInfo + uSystemInfoLen, &uCpuID, sizeof( UINT ) );
		uSystemInfoLen += sizeof( UINT );

		//uCpuID = strlen( ( char* )szCpu );
		//CopyMemory( szSystemInfo + uSystemInfoLen, szCpu, uCpuID );
		//uSystemInfoLen += uCpuID;

		rv = MSCAPIErrCodeSuccess;
	}
	else		
	{
		rv = MSCAPIErrCodeFailure;
	}

	if (rv)
	{

	}
	else
	{
		if(NULL == pszSN)
		{
			*puiSNLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeSuccess;
		}
		else if(*puiSNLen < uSystemInfoLen*2+1)
		{
			*puiSNLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeMemLess;
		}
		else
		{
			*puiSNLen=uSystemInfoLen*2+1;
			OPF_Bin2Str(szSystemInfo,uSystemInfoLen,pszSN,puiSNLen);
			rv = MSCAPIErrCodeSuccess;
		}
	}

	return rv;
}


unsigned int MSCAPI_ReadHardDiskSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag)
{
	int rv = MSCAPIErrCodeSuccess;
	BYTE szSystemInfo[BUFFER_LEN_1K] = {0}; // 在程序执行完毕后，此处存储取得的系统特征码
	UINT uSystemInfoLen = 0; // 在程序执行完毕后，此处存储取得的系统特征码的长度
	OSVERSIONINFO ovi = { 0 };
	ovi.dwOSVersionInfoSize = sizeof( OSVERSIONINFO );
	GetVersionEx( &ovi );

	if( ovi.dwPlatformId != VER_PLATFORM_WIN32_NT )
	{
		// Only Windows 2000, Windows XP, Windows Server 2003...
		rv = MSCAPIErrCodeFailure;
	}
	else
	{
		if( !WinNTHDSerialNumAsPhysicalRead( szSystemInfo, &uSystemInfoLen, 1024 ) )
		{
			if(WinNTHDSerialNumAsScsiRead( szSystemInfo, &uSystemInfoLen, 1024 ))
			{
				rv = MSCAPIErrCodeSuccess;
			}
			else
			{
				rv = MSCAPIErrCodeFailure;
			}
		}
		else
		{
			rv = MSCAPIErrCodeSuccess;
		}
	}

	if (rv)
	{

	}
	else
	{
		if(NULL == pszSN)
		{
			*puiSNLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeSuccess;
		}
		else if(*puiSNLen < uSystemInfoLen*2+1)
		{
			*puiSNLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeMemLess;
		}
		else
		{
			*puiSNLen=uSystemInfoLen*2+1;
			OPF_Bin2Str(szSystemInfo,uSystemInfoLen,pszSN,puiSNLen);
			rv = MSCAPIErrCodeSuccess;
		}
	}

	return rv;
}

unsigned int MSCAPI_ReadHostMACAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag)
{
	int rv = MSCAPIErrCodeSuccess;
	IP_ADAPTER_INFO iai;
	ULONG uSize = 0;
	DWORD dwResult = GetAdaptersInfo( &iai, &uSize );

	BYTE szSystemInfo[BUFFER_LEN_1K] = {0}; // 在程序执行完毕后，此处存储取得的系统特征码
	UINT uSystemInfoLen = 0; // 在程序执行完毕后，此处存储取得的系统特征码的长度

	if( dwResult == ERROR_BUFFER_OVERFLOW )
	{
		IP_ADAPTER_INFO* piai = ( IP_ADAPTER_INFO* )HeapAlloc( GetProcessHeap( ), 0, uSize );
		if( piai != NULL )
		{
			dwResult = GetAdaptersInfo( piai, &uSize );
			if( ERROR_SUCCESS == dwResult )
			{
				IP_ADAPTER_INFO* piai2 = piai;
				while( piai2 != NULL && ( uSystemInfoLen + piai2->AddressLength ) < 4096U )
				{
					//CopyMemory( szSystemInfo + uSystemInfoLen, piai2->Address, piai2->AddressLength );
					//uSystemInfoLen += piai2->AddressLength;
					//piai2 = piai2->Next;
					unsigned int tempLen = 4096U-uSystemInfoLen;

					OPF_Bin2Str( piai2->Address, piai2->AddressLength,(char *)szSystemInfo + uSystemInfoLen, &tempLen);
					uSystemInfoLen += tempLen;
					szSystemInfo[uSystemInfoLen] = ' ';
					uSystemInfoLen += 1;
					piai2 = piai2->Next;  
				}
			}
			else
			{
				//uErrorCode = 0xF0000000U + dwResult;
				rv = MSCAPIErrCodeFailure;
			}
			HeapFree( GetProcessHeap( ), 0, piai);
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		//uErrorCode = 0xE0000000U + dwResult;
		rv = MSCAPIErrCodeFailure;
	}

	if (rv)
	{

	}
	else
	{
		//if(NULL == pszAddress)
		//{
		//	*puiAddressLen=uSystemInfoLen*2+1;
		//	rv = MSCAPIErrCodeSuccess;
		//}
		//else if(*puiAddressLen < uSystemInfoLen*2+1)
		//{
		//	*puiAddressLen=uSystemInfoLen*2+1;
		//	rv = MSCAPIErrCodeMemLess;
		//}
		//else
		//{
		//	*puiAddressLen=uSystemInfoLen*2+1;
		//	OPF_Bin2Str(szSystemInfo,uSystemInfoLen,pszAddress,puiAddressLen);
		//	rv = MSCAPIErrCodeSuccess;
		//}
		if(NULL == pszAddress)
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeSuccess;
		}
		else if(*puiAddressLen < uSystemInfoLen*2+1)
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeMemLess;
		}
		else
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			strcpy(pszAddress,(char*)szSystemInfo);
			rv = MSCAPIErrCodeSuccess;
		}
	}

	return rv;
}


unsigned int MSCAPI_ReadHostIPAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag)
{
	int rv = MSCAPIErrCodeSuccess;
	IP_ADAPTER_INFO iai;
	ULONG uSize = 0;
	DWORD dwResult = GetAdaptersInfo( &iai, &uSize );

	BYTE szSystemInfo[BUFFER_LEN_1K] = {0}; // 在程序执行完毕后，此处存储取得的系统特征码
	UINT uSystemInfoLen = 0; // 在程序执行完毕后，此处存储取得的系统特征码的长度

	if( dwResult == ERROR_BUFFER_OVERFLOW )
	{
		IP_ADAPTER_INFO* piai = ( IP_ADAPTER_INFO* )HeapAlloc( GetProcessHeap( ), 0, uSize );
		if( piai != NULL )
		{
			dwResult = GetAdaptersInfo( piai, &uSize );
			if( ERROR_SUCCESS == dwResult )
			{
				IP_ADAPTER_INFO* piai2 = piai;

				char type[64] = { 0 };


				while( piai2 != NULL && ( uSystemInfoLen + strlen(piai2->IpAddressList.IpAddress.String) ) < 4096U )
				{
					CopyMemory( szSystemInfo + uSystemInfoLen, piai2->IpAddressList.IpAddress.String, strlen(piai2->IpAddressList.IpAddress.String) );
					uSystemInfoLen += strlen(piai2->IpAddressList.IpAddress.String);
					szSystemInfo[uSystemInfoLen] = ' ';
					uSystemInfoLen += 1;

					sprintf(type, "type=%d", piai2->Type);
					strcat((char*)szSystemInfo, type);
					uSystemInfoLen += strlen(type);


					szSystemInfo[uSystemInfoLen] = ' ';
					uSystemInfoLen += 1;

					piai2 = piai2->Next;                        
				}
			}
			else
			{
				//uErrorCode = 0xF0000000U + dwResult;
				rv = MSCAPIErrCodeFailure;
			}
			HeapFree( GetProcessHeap( ), 0, piai);
		}
		else
		{
			return FALSE;
		}
	}
	else
	{
		//uErrorCode = 0xE0000000U + dwResult;
		rv = MSCAPIErrCodeFailure;
	}

	if (rv)
	{

	}
	else
	{
		if(NULL == pszAddress)
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeSuccess;
		}
		else if(*puiAddressLen < uSystemInfoLen*2+1)
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			rv = MSCAPIErrCodeMemLess;
		}
		else
		{
			*puiAddressLen=uSystemInfoLen*2+1;
			strcpy(pszAddress,(char*)szSystemInfo);
			rv = MSCAPIErrCodeSuccess;
		}
	}

	return rv;
}


unsigned int MSCAPI_ReadHostAddress(STHostAddress *pszAddress, unsigned int *puiAddressLen)
{
	int rv = MSCAPIErrCodeSuccess;
	IP_ADAPTER_INFO iai;
	ULONG uSize = 0;
	DWORD dwResult = GetAdaptersInfo(&iai, &uSize);
	
	if (dwResult == ERROR_BUFFER_OVERFLOW)
	{
		IP_ADAPTER_INFO* piai = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), 0, uSize);
		if (piai != NULL)
		{
			dwResult = GetAdaptersInfo(piai, &uSize);
			if (ERROR_SUCCESS == dwResult)
			{
				IP_ADAPTER_INFO* piai2 = piai;
				int i = 0;
				char buffer[32] = { 0 };

				while (piai2 != NULL)
				{
					i++;
					piai2 = piai2->Next;
				}

				if (NULL == pszAddress)
				{
					*puiAddressLen = i;
					rv = MSCAPIErrCodeSuccess;
				}
				else if (*puiAddressLen < i)
				{
					*puiAddressLen = i;
					rv = MSCAPIErrCodeMemLess;
				}
				else
				{
					*puiAddressLen = i;
					memset(pszAddress, 0, sizeof(STHostAddress) * i);

					piai2 = piai;
					i = 0;

					while (piai2 != NULL)
					{
						memcpy(pszAddress[i].szIPAddress, piai2->IpAddressList.IpAddress.String, strlen(piai2->IpAddressList.IpAddress.String));

						memset(buffer, 0, 32);

						sprintf(buffer, "%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x-",
							piai2->AddressLength > 0 ? piai2->Address[0] : 0,
							piai2->AddressLength > 1 ? piai2->Address[1] : 0,
							piai2->AddressLength > 2 ? piai2->Address[2] : 0,
							piai2->AddressLength > 3 ? piai2->Address[3] : 0,
							piai2->AddressLength > 4 ? piai2->Address[4] : 0,
							piai2->AddressLength > 5 ? piai2->Address[5] : 0,
							piai2->AddressLength > 6 ? piai2->Address[6] : 0,
							piai2->AddressLength > 7 ? piai2->Address[7] : 0
						);

						memcpy(pszAddress[i].szMacAddress, buffer, piai2->AddressLength * 3 - 1);

						i++;
						piai2 = piai2->Next;
					}
				}
			}
			else
			{
				//uErrorCode = 0xF0000000U + dwResult;
				rv = MSCAPIErrCodeFailure;
			}
			HeapFree(GetProcessHeap(), 0, piai);
		}
		else
		{
			//uErrorCode = 0xE0000000U + dwResult;
			rv = MSCAPIErrCodeFailure;
		}
	}
	else
	{
		//uErrorCode = 0xE0000000U + dwResult;
		rv = MSCAPIErrCodeFailure;
	}

	return rv;
}


unsigned int MSCAPI_CalcHWInfoHash(char *pszCpuSN,char *pszMacSN, char *pszHostMacAddress, char *pszHostIPAddress,char * pszHash,unsigned int *puiHashLen, int iFlag)
{
	return 0;
}

BOOL GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
	BOOL bRet= FALSE;
	HMODULE hModNtdll= NULL;
	if (hModNtdll= ::LoadLibrary("ntdll.dll"))
	{
		typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
		pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
		pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
		if (pfRtlGetNtVersionNumbers)
		{
			pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
			dwBuildNumber&= 0x0ffff;
			bRet = TRUE;
		}

		::FreeLibrary(hModNtdll);
		hModNtdll = NULL;
	}

	return bRet;
}



unsigned int MSCAPI_ReadSystemVersionInfo(char * pszSysInfo,unsigned int *puiSysInfoLen, int iFlag)
{
	SYSTEM_INFO si;
	OSVERSIONINFOEX osvi;
	DWORD dwType; 
	std::string os = "";
	int rv = MSCAPIErrCodeSuccess;

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX)); 
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	BOOL bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi); 
	if(bOsVersionInfoEx == 0)
		return false; // Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.

	PGNSI pGNSI = (PGNSI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if(NULL != pGNSI)
		pGNSI(&si);
	else 
		GetSystemInfo(&si); // Check for unsupported OS



	if(TRUE == GetNtVersionNumbers(osvi.dwMajorVersion,osvi.dwMinorVersion,osvi.dwBuildNumber))
	{
		//
	}


	// 忽略早期版本
	if (VER_PLATFORM_WIN32_NT != osvi.dwPlatformId || osvi.dwMajorVersion <= 4 ) {
		rv = MSCAPIErrCodeFailure;
		goto err;
	} 

	os += "Microsoft "; 

	// Test for the specific product. 

	if (osvi.dwMajorVersion == 10)
	{
		os += "Windows 10 ";
	}
	else if ( osvi.dwMajorVersion == 6 ){

		if( osvi.dwMinorVersion == 0 ){
			if( osvi.wProductType == VER_NT_WORKSTATION )
				os += "Windows Vista ";
			else os += "Windows Server 2008 ";
		}  
		else if ( osvi.dwMinorVersion == 1 ){
			if( osvi.wProductType == VER_NT_WORKSTATION )
				os += "Windows 7 ";
			else os += "Windows Server 2008 R2 ";
		}  
		else if (osvi.dwMinorVersion == 2){
			if (osvi.wProductType == VER_NT_WORKSTATION)
				os += "Windows 8 ";
			else
				os += "Windows Server 2012 ";
		}
		else if (osvi.dwMinorVersion == 3){
			if (osvi.wProductType == VER_NT_WORKSTATION)
				os += "Windows 8.1 ";
			else
				os += "Windows Server 2012 R2 ";
		}
	} 

	PGPI pGPI = (PGPI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
	if (pGPI)
	{
		pGPI( osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);  
	}


	switch( dwType ){
	case PRODUCT_ULTIMATE:
		os += "Ultimate Edition";
		break;
	case PRODUCT_PROFESSIONAL:
		os += "Professional";
		break;
	case PRODUCT_HOME_PREMIUM:
		os += "Home Premium Edition";
		break;
	case PRODUCT_HOME_BASIC:
		os += "Home Basic Edition";
		break;
	case PRODUCT_ENTERPRISE:
		os += "Enterprise Edition";
		break;
	case PRODUCT_BUSINESS:
		os += "Business Edition";
		break;
	case PRODUCT_STARTER:
		os += "Starter Edition";
		break;
	case PRODUCT_CLUSTER_SERVER:
		os += "Cluster Server Edition";
		break;
	case PRODUCT_DATACENTER_SERVER:
		os += "Datacenter Edition";
		break;
	case PRODUCT_DATACENTER_SERVER_CORE:
		os += "Datacenter Edition (core installation)";
		break;
	case PRODUCT_ENTERPRISE_SERVER:
		os += "Enterprise Edition";
		break;
	case PRODUCT_ENTERPRISE_SERVER_CORE:
		os += "Enterprise Edition (core installation)";
		break;
	case PRODUCT_ENTERPRISE_SERVER_IA64:
		os += "Enterprise Edition for Itanium-based Systems";
		break;
	case PRODUCT_SMALLBUSINESS_SERVER:
		os += "Small Business Server";
		break;
	case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
		os += "Small Business Server Premium Edition";
		break;
	case PRODUCT_STANDARD_SERVER:
		os += "Standard Edition";
		break;
	case PRODUCT_STANDARD_SERVER_CORE:
		os += "Standard Edition (core installation)";
		break;
	case PRODUCT_WEB_SERVER:
		os += "Web Server Edition";
		break;
	}

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 ){
		if( GetSystemMetrics(SM_SERVERR2) )
			os +=  "Windows Server 2003 R2, ";
		else if ( osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER )
			os +=  "Windows Storage Server 2003";
		else if ( osvi.wSuiteMask & VER_SUITE_WH_SERVER )
			os +=  "Windows Home Server";
		else if( osvi.wProductType == VER_NT_WORKSTATION &&
			si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64){
				os +=  "Windows XP Professional x64 Edition";
		} else os += "Windows Server 2003, ";  

		// Test for the server type.
		if ( osvi.wProductType != VER_NT_WORKSTATION ){
			if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64 ){
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					os +=  "Datacenter Edition for Itanium-based Systems";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					os +=  "Enterprise Edition for Itanium-based Systems";
			}   
			else if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 ){
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					os +=  "Datacenter x64 Edition";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					os +=  "Enterprise x64 Edition";
				else 
					os +=  "Standard x64 Edition";
			}   
			else {
				if ( osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER )
					os +=  "Compute Cluster Edition";
				else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					os +=  "Datacenter Edition";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					os +=  "Enterprise Edition";
				else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
					os +=  "Web Edition";
				else 
					os +=  "Standard Edition";
			}
		}
	} 

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 ){
		os += "Windows XP ";
		if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
			os +=  "Home Edition";
		else 
			os +=  "Professional";
	} 

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 ){
		os += "Windows 2000 ";  
		if ( osvi.wProductType == VER_NT_WORKSTATION ){
			os +=  "Professional";
		}
		else {
			if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
				os +=  "Datacenter Server";
			else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
				os +=  "Advanced Server";
			else 
				os +=  "Server";
		}
	}

	// Include service pack (if any) and build number. 
	if(strlen(osvi.szCSDVersion) > 0) {
		os += " ";
		os += osvi.szCSDVersion;
	}
	os += " (build ";
	{
		char dataBuildNumber[BUFFER_LEN_1K]  = {0};

		sprintf(dataBuildNumber, "%d", osvi.dwBuildNumber);

		os += dataBuildNumber;
	}
	os += ")"; 

	// 32位，64位
	if ( osvi.dwMajorVersion >= 6 ) {
		if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			os +=  ", 64-bit";
		else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL )
			os += ", 32-bit";
	} 

	if(NULL == pszSysInfo)
	{
		*puiSysInfoLen=os.length()+1;
		rv = MSCAPIErrCodeSuccess;
	}
	else if(*puiSysInfoLen < os.length()+1)
	{
		*puiSysInfoLen=os.length()+1;
		rv = MSCAPIErrCodeMemLess;
	}
	else
	{
		*puiSysInfoLen=os.length()+1;
		strcpy(pszSysInfo,os.c_str());
		rv = MSCAPIErrCodeSuccess;
	}
err:

	return rv;
}

unsigned int MSCAPI_ReadBrowserVersionInfo(char * pszBrowserInfo,unsigned int *puiBrowserInfoLen, int iFlag)
{
	std::string sysInfo;
	bool isWin7 = sysInfo.find("Windows 7")!=std::string::npos;
	std::wstring httpProg =L"";
	
	int rv = MSCAPIErrCodeSuccess;
	std::string	fileInfo;
	std::string	filePath;
	std::string fileVersion;
	std::vector<std::wstring> tmp;
	int i = 0;

	isWin7 = true;

	// 如果是win7，读取特定的注册表位置
	if (isWin7){
		std::wstring reg_path(L"Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\http\\UserChoice\\");
		std::wstring reg_key(L"Progid");
		std::wstring reg_value;

		// 读取默认浏览器
		RegKey programKey(HKEY_CURRENT_USER, reg_path.c_str(), KEY_READ);
		if (programKey.ReadValue(reg_key.c_str(), &reg_value) != ERROR_SUCCESS) {
			RegKey programMachineKey(HKEY_LOCAL_MACHINE, reg_path.c_str(), KEY_READ);
			if (programMachineKey.ReadValue(reg_key.c_str(), &reg_value)!= ERROR_SUCCESS)
			{
				rv = MSCAPIErrCodeFailure;
			}
		}

		reg_path = reg_value + L"\\shell\\open\\command\\";
		RegKey programKey2(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ);
		if (programKey2.ReadValue(NULL, &httpProg) != ERROR_SUCCESS) {
			rv = MSCAPIErrCodeFailure;
		}
	}

	if (httpProg.empty()){
		std::wstring reg_path(L"http\\shell\\open\\command\\");
		RegKey programKey(HKEY_CLASSES_ROOT, reg_path.c_str(), KEY_READ);
		if (programKey.ReadValue(NULL, &httpProg) != ERROR_SUCCESS) {
			rv = MSCAPIErrCodeFailure;
			goto err;
		}
	}

	tmp = split(httpProg, '"');

	for (i = 0; i < tmp.size(); i ++)
	{
		if (tmp[i].length() > 0)
		{
			filePath = utf8_encode(tmp[i]);
			break;
		}
	}

	if (filePath.length() > 0)
	{
		std::fstream _file;
		_file.open(filePath.c_str(),ios::in);

		if(_file)
		{
			char     szDllver[50];
			DWORD    dwSize=0;
			BYTE     *pbVersionInfo=NULL;                 // 获取文件版本信息
			VS_FIXEDFILEINFO    *pFileInfo=NULL; 
			UINT                puLenFileInfo=0; 
			dwSize=GetFileVersionInfoSize(filePath.c_str(), NULL);
			pbVersionInfo=new BYTE[dwSize]; 
			if(!GetFileVersionInfo(filePath.c_str(),0,dwSize,pbVersionInfo))
			{
				delete[]pbVersionInfo; 
			}
			if (!VerQueryValue(pbVersionInfo,TEXT("\\"),(LPVOID*)&pFileInfo,&puLenFileInfo)) 
			{ 
				delete[]pbVersionInfo; 
			}
			WORD d1 = HIWORD(pFileInfo->dwFileVersionMS);
			WORD d2 = LOWORD(pFileInfo->dwFileVersionMS);
			WORD d3 = HIWORD(pFileInfo->dwFileVersionLS);
			WORD d4 = LOWORD(pFileInfo->dwFileVersionLS);
			sprintf(szDllver,"%d.%d.%d.%d",d1,d2,d3,d4);
			delete[]pbVersionInfo;

			fileVersion = szDllver;
		}
	}

	fileInfo += filePath;
	fileInfo += ' ';
	fileInfo += fileVersion;

	if(NULL == pszBrowserInfo)
	{
		*puiBrowserInfoLen=fileInfo.length()+1;
		rv = MSCAPIErrCodeSuccess;
	}
	else if(*puiBrowserInfoLen < fileInfo.length()+1)
	{
		*puiBrowserInfoLen=fileInfo.length()+1;
		rv = MSCAPIErrCodeMemLess;
	}
	else
	{
		*puiBrowserInfoLen=fileInfo.length()+1;
		strcpy(pszBrowserInfo,fileInfo.c_str());
		rv = MSCAPIErrCodeSuccess;
	}
	
err:


	return rv;
}

unsigned int MSCAPI_ReadClientCSPInfo(char * pszCSPInfo,unsigned int *puiCSPInfoLen, int iFlag)
{
	return 0;
}