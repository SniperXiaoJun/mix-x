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

bool getPublicIp(string& ip)
{
	int    sock;
	char **pptr = NULL;
	struct sockaddr_in    destAddr;
	struct hostent    *ptr = NULL;
	char destIP[128];

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (-1 == sock) {
		perror("creat socket failed");
		return false;
	}
	memset((void *)&destAddr, 0, sizeof(destAddr));
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(80);
	ptr = gethostbyname("www.ip138.com");
	if (NULL == ptr) {
		perror("gethostbyname error");
		return false;
	}
	for (pptr = ptr->h_addr_list; NULL != *pptr; ++pptr) {
		inet_ntop(ptr->h_addrtype, *pptr, destIP, sizeof(destIP));
		printf("addr:%s\n", destIP);
		ip = destIP;
		return true;
	}
	return true;
}

int main()
{
	string strPublicIp;
	char buffer_ip[1024] = {0};
	unsigned buffer_ip_len = 1024;

#if defined(WIN32)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
		return -1;
	}
#endif

	getPublicIp(strPublicIp);

	MSCAPI_ReadHostIPAddress(buffer_ip, &buffer_ip_len, 0);

	printf("outter ip=%s\ninner ip=%s\n\n", strPublicIp.c_str(), buffer_ip);

	return getchar();
}