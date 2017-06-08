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

bool getPublicIp(string& ip)
{
	char peer[] = "GET / HTTP/1.1\r\n"
		"Host:ip.dnsexit.com\r\n\r\n";
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in addr;
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

	ip = &text[i + 5];//得到ip地址开始位置，复制到字符串ip中  

	closesocket(sock);

	return true;
}
