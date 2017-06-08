


#ifndef _HTTPCONNECT_H
#define _HTTPCONNECT_H

#ifdef __cplusplus
extern "C"{
#endif
	unsigned int HttpConnect(const char * pszSite,const char * pszSub ,unsigned int uiPort);
	unsigned int SSLConnect(const char * pszSite,const char * pszSub, unsigned int uiPort, unsigned int uiTimeOutSecond);
#ifdef __cplusplus
}
#endif


#endif/*_HTTPCONNECT_H*/


