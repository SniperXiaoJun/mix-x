#ifndef __CERTIFICATE_ITEM_PARASE_H__
#define __CERTIFICATE_ITEM_PARASE_H__


typedef enum _ECertificateItem
{
	ECertificateItem_Version = 0,

}ECertificateItem;


typedef enum _ECertificate_KEY_ALG
{
	ECertificate_KEY_ALG_UNKNOW = 0,
	ECertificate_KEY_ALG_RSA = 1,
	ECertificate_KEY_ALG_EC = 2,
	ECertificate_KEY_ALG_DSA = 3,
	ECertificate_KEY_ALG_DH = 4,
}ECertificate_KEY_ALG;


#define CERT_SIGNATURE_ALG_RSA_RSA          "1.2.840.113549.1.1.1"  
#define CERT_SIGNATURE_ALG_MD2RSA           "1.2.840.113549.1.1.2"  
#define CERT_SIGNATURE_ALG_MD4RSA           "1.2.840.113549.1.1.3"  
#define CERT_SIGNATURE_ALG_MD5RSA           "1.2.840.113549.1.1.4"  
#define CERT_SIGNATURE_ALG_SHA1RSA          "1.2.840.113549.1.1.5"  
#define CERT_SIGNATURE_ALG_SHA256RSA        "1.2.840.113549.1.1.11"  
#define CERT_SIGNATURE_ALG_SM3SM2           "1.2.156.10197.1.501"  


// c fucntions
#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

// cpp fucctions
#ifdef __cplusplus

typedef struct x509_st X509;

#include <string>

class CertificateItemParse
{
public:
	CertificateItemParse();

	~CertificateItemParse();

	int parse();
	int setCertificate(const unsigned char * pCert, unsigned int uiCertLen);

//private:
	X509 *m_pX509;
	int m_iVersion;
	ECertificate_KEY_ALG m_iKeyAlg;

	//#define KU_DIGITAL_SIGNATURE	0x0080
	//#define KU_NON_REPUDIATION	0x0040
	//#define KU_KEY_ENCIPHERMENT	0x0020
	//#define KU_DATA_ENCIPHERMENT	0x0010
	//#define KU_KEY_AGREEMENT	0x0008
	//#define KU_KEY_CERT_SIGN	0x0004
	//#define KU_CRL_SIGN		0x0002
	//#define KU_ENCIPHER_ONLY	0x0001
	//#define KU_DECIPHER_ONLY	0x8000
	unsigned long m_ulKeyUsage;

	std::string m_strVersion;
	std::string m_strSerialNumber;
	std::string m_strOID;
	std::string m_strIssue;
	std::string m_strSubject;
	std::string m_strIssueCN;
	std::string m_strSubjectCN;

	time_t m_tNotBefore;
	time_t m_tNotAfter;
	std::string m_strNotBefore;
	std::string m_strNotAfter;
};


#endif


#endif __CERTIFICATE_ITEM_PARASE_H__