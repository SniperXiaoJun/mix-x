#include <string> //进程快照函数头文件  
#include <stdio.h>  

#if !defined(WIN32)
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <io.h>
#pragma warning(push, 3)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)

typedef int ssize_t;
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"iphlpapi.lib") 
#endif

using namespace std;

#include "msclient_api.h"

bool getPublicIp(string& ip_remote, string &ip_local)
{
	char peer[] = "GET / HTTP/1.1\r\n"
		"Host:ip.dnsexit.com\r\n\r\n";
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr;
	sockaddr_in addr_tmp = { 0 };
	string strDest;

	char buffer[1024] = { 0 };

	int addr_in_len = sizeof(sockaddr_in);

	char text[600] = { 0 };
	int i = 0;

	if (-1 == sock) {
		perror("creat socket failed");
		return false;
	}

	hostent *ptr = gethostbyname("ip.dnsexit.com");//获取主机地址  

	if (NULL == ptr) {
		perror("gethostbyname error");
		return false;
	}

	addr.sin_addr = *(in_addr*)ptr->h_addr_list[0];//使用地址列表的第一个进行连接，实际上也只有这一个  
	addr.sin_family = 2;
	addr.sin_port = htons(80);//http的80端口  
	if (-1 == connect(sock, (sockaddr*)&addr, sizeof(sockaddr_in)))
	{
		perror("connect error");
		return false;
	}

	if (-1 == getpeername(sock, (sockaddr*)&addr_tmp, &addr_in_len))
	{
		perror("getpeername failed");
		return false;
	}

	memset(buffer, 0, 1024);
	sprintf(buffer, "%d.%d.%d.%d", addr_tmp.sin_addr.S_un.S_un_b.s_b1, addr_tmp.sin_addr.S_un.S_un_b.s_b2, addr_tmp.sin_addr.S_un.S_un_b.s_b3, addr_tmp.sin_addr.S_un.S_un_b.s_b4);
	strDest = buffer;

	if (-1 == getsockname(sock, (sockaddr*)&addr_tmp, &addr_in_len))
	{
		perror("getsockname failed");
		return false;
	}

	memset(buffer, 0, 1024);
	sprintf(buffer, "%d.%d.%d.%d", addr_tmp.sin_addr.S_un.S_un_b.s_b1, addr_tmp.sin_addr.S_un.S_un_b.s_b2, addr_tmp.sin_addr.S_un.S_un_b.s_b3, addr_tmp.sin_addr.S_un.S_un_b.s_b4);
	ip_local = buffer;

	if (-1 == send(sock, peer, sizeof(peer), 0))
	{
		perror("send error");
		return false;
	}

	if (-1 == recv(sock, text, sizeof(text), 0))
	{
		perror("recv error");
		return false;
	}

	while (text[i] != '\n' || text[i + 1] != '\r')//去掉前面的信息  
		i++;

	ip_remote = &text[i + 5];//得到ip地址开始位置，复制到字符串ip中  

	closesocket(sock);

	return true;
}

int main()
{
	string strRemoteIp;
	string strLocalIp;

	STHostAddress *address = NULL;
	unsigned int address_len = 0;

	size_t i;
#if defined(WIN32)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
		return -1;
	}
#endif

	getPublicIp(strRemoteIp, strLocalIp);

	MSCAPI_ReadHostAddress(address, &address_len);

	address = (STHostAddress*)malloc(sizeof(STHostAddress)*address_len);

	MSCAPI_ReadHostAddress(address, &address_len);

	for (i = 0; i < address_len; i++)
	{
		if (0 == strcmp(address[i].szIPAddress, strLocalIp.c_str()))
		{
			break;
		}
	}

	printf("outter ip=%s\ninner ip=%s\nmac=%s\n\n", strRemoteIp.c_str(), strLocalIp.c_str(), address[i].szMacAddress);

	free(address);

	return getchar();
}