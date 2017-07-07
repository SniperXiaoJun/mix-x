#pragma once
#include <atlbase.h>
#include <atlconv.h>
#include "iphlpapi.h"
#pragma comment(lib,"Iphlpapi.lib")



class GetMacAddress
{
public:
	GetMacAddress();
	~GetMacAddress();

	const char * GetMac();

//private:
//	string m_Mac;
};

