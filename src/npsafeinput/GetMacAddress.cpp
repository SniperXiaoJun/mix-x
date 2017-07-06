#include "GetMacAddress.h"
#include <iostream>using namespace std;

GetMacAddress::GetMacAddress()
{
}


GetMacAddress::~GetMacAddress()
{
}

const char * GetMacAddress::GetMac(){
	std::string str;
    //PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //�õ��ṹ���С,����GetAdaptersInfo����
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
    int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    if (ERROR_BUFFER_OVERFLOW==nRel)
    {
		//����������ص���ERROR_BUFFER_OVERFLOW
		//��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
		//��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
		//�ͷ�ԭ�����ڴ�ռ�
        delete pIpAdapterInfo;
        //���������ڴ�ռ������洢����������Ϣ
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        //�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
        nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);    
    }
    if (ERROR_SUCCESS==nRel)
    {
        //���������Ϣ
		//�����ж�����,���ͨ��ѭ��ȥ�ж�
		while (pIpAdapterInfo)
		{
			//cout<<"�������ƣ�"<<pIpAdapterInfo->AdapterName<<endl;
			//cout<<"����������"<<pIpAdapterInfo->Description<<endl;
			//cout<<"����MAC��ַ��"<<pIpAdapterInfo->Address;
			for (UINT i = 0; i < pIpAdapterInfo->AddressLength; i++)
			if (i==pIpAdapterInfo->AddressLength-1)
			{
				//strcpy(m_Mac, (char *)pIpAdapterInfo->Address[i]);
				MessageBoxA(NULL,(char *)pIpAdapterInfo->Address[i],"",0);
				//str.append((char *)pIpAdapterInfo->Address[i]).append("|");
				//str+=(char *)pIpAdapterInfo->Address[i]+"|";
				//m_Mac+=(char *)pIpAdapterInfo->Address[i]+"\n";
				printf("%02x\n", pIpAdapterInfo->Address[i]);
			}
			else
			{
				MessageBoxA(NULL,(char *)pIpAdapterInfo->Address[i],"",0);
//				str.append((char *)pIpAdapterInfo->Address[i]).append("-");
				//str+=(char *)pIpAdapterInfo->Address[i]+"-";
				printf("%02x-", pIpAdapterInfo->Address[i]);
			}
			//cout<<"����IP��ַ���£�"<<endl;
			//���������ж�IP,���ͨ��ѭ��ȥ�ж�
			//IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
			//do 
			//{
			//	cout<<pIpAddrString->IpAddress.String<<endl;
			//	pIpAddrString=pIpAddrString->Next;
			//} while (pIpAddrString);
			//pIpAdapterInfo = pIpAdapterInfo->Next;
			//cout<<"*****************************************************"<<endl;
		}
    }
    //�ͷ��ڴ�ռ�
    if (pIpAdapterInfo)
    {
        delete pIpAdapterInfo;
    }
	MessageBoxA(NULL,str.c_str(),"",0);
	return str.c_str();
}
