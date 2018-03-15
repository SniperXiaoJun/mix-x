#include "certificate_items_parse.h"

#include "common.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>



/*
string to time_t
时间格式 2009-3-24 0:00:08 或 2009-3-24
*/
#include <string.h>
using namespace std;

static int API_StringToTimeEX(const string &strDateStr, time_t &timeData)
{
	char *pBeginPos = (char*)strDateStr.c_str();
	char *pPos = strstr(pBeginPos, "-");
	if (pPos == NULL)
	{
		printf("strDateStr[%s] err \n", strDateStr.c_str());
		return -1;
	}
	int iYear = atoi(pBeginPos);
	int iMonth = atoi(pPos + 1);
	pPos = strstr(pPos + 1, "-");
	if (pPos == NULL)
	{
		printf("strDateStr[%s] err \n", strDateStr.c_str());
		return -1;
	}
	int iDay = atoi(pPos + 1);
	int iHour = 0;
	int iMin = 0;
	int iSec = 0;
	pPos = strstr(pPos + 1, " ");
	//为了兼容有些没精确到时分秒的
	if (pPos != NULL)
	{
		iHour = atoi(pPos + 1);
		pPos = strstr(pPos + 1, ":");
		if (pPos != NULL)
		{
			iMin = atoi(pPos + 1);
			pPos = strstr(pPos + 1, ":");
			if (pPos != NULL)
			{
				iSec = atoi(pPos + 1);
			}
		}
	}

	struct tm sourcedate;
	memset((void*)&sourcedate, 0, sizeof(sourcedate));
	sourcedate.tm_sec = iSec;
	sourcedate.tm_min = iMin;
	sourcedate.tm_hour = iHour;
	sourcedate.tm_mday = iDay;
	sourcedate.tm_mon = iMonth - 1;
	sourcedate.tm_year = iYear - 1900;
	timeData = mktime(&sourcedate);
	return 0;
}
/*
time_t to string 时间格式 2009-3-24 0:00:08
*/
static int API_TimeToStringEX(string &strDateStr, const time_t &timeData)
{
	char chTmp[100];
	memset(chTmp, 0, sizeof(chTmp));
	struct tm *p;
	p = localtime(&timeData);
	p->tm_year = p->tm_year + 1900;
	p->tm_mon = p->tm_mon + 1;

	snprintf(chTmp, sizeof(chTmp), "%04d-%02d-%02d %02d:%02d:%02d",
		p->tm_year, p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);
	strDateStr = chTmp;
	return 0;
}



CertificateItemParse::CertificateItemParse()
{
	m_pX509 = NULL;
}


CertificateItemParse::~CertificateItemParse()
{
	if (m_pX509)
	{
		// free
		X509_free(m_pX509);
		m_pX509 = NULL;
	}
}

//-------------------------------------------------------------------------------------------------
static int mypint(const char ** s,

	int n,

	int min,

	int max,

	int * e

)

{

	int retval = 0;

	while (n) {

		if (**s < '0' || **s > '9') { *e = 1; return 0; }

		retval *= 10;

		retval += **s - '0';

		--n; ++(*s);

	}

	if (retval < min || retval > max) *e = 1;

	return retval;

}

static time_t ASN1_TIME_get(ASN1_TIME * a,

	int *err

)

{

	char days[2][12] =

	{

		{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },

		{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }

	};

	int dummy;

	const char *s;

	int generalized;

	struct tm t;

	time_t i, year, isleap, offset;

	time_t retval;

	if (err == NULL) err = &dummy;

	if (a->type == V_ASN1_GENERALIZEDTIME) {

		generalized = 1;

	}
	else if (a->type == V_ASN1_UTCTIME) {

		generalized = 0;

	}
	else {

		*err = 1;

		return 0;

	}

	s = (const char*)a->data; // Data should be always null terminated

	if (s == NULL || s[a->length] != '\0') {

		*err = 1;

		return 0;

	}


	*err = 0;

	if (generalized) {

		t.tm_year = mypint(&s, 4, 0, 9999, err) - 1900;

	}
	else {

		t.tm_year = mypint(&s, 2, 0, 99, err);

		if (t.tm_year < 50) t.tm_year += 100;

	}

	t.tm_mon = mypint(&s, 2, 1, 12, err) - 1;

	t.tm_mday = mypint(&s, 2, 1, 31, err);

	// NOTE: It's not yet clear, if this implementation is 100% correct

	// for GeneralizedTime... but at least misinterpretation is

	// impossible --- we just throw an exception

	t.tm_hour = mypint(&s, 2, 0, 23, err);

	t.tm_min = mypint(&s, 2, 0, 59, err);

	if (*s >= '0' && *s <= '9') {

		t.tm_sec = mypint(&s, 2, 0, 59, err);

	}
	else {

		t.tm_sec = 0;

	}

	if (*err) return 0; // Format violation

	if (generalized) {

		// skip fractional seconds if any

		while (*s == '.' || *s == ',' || (*s >= '0' && *s <= '9')) ++s;

		// special treatment for local time

		if (*s == 0) {

			t.tm_isdst = -1;

			retval = mktime(&t); // Local time is easy :)

			if (retval == (time_t)-1) {

				*err = 2;

				retval = 0;

			}

			return retval;

		}

	}

	if (*s == 'Z') {

		offset = 0;

		++s;

	}
	else if (*s == '-' || *s == '+') {

		i = (*s++ == '-');

		offset = mypint(&s, 2, 0, 12, err);

		offset *= 60;

		offset += mypint(&s, 2, 0, 59, err);

		if (*err) return 0; // Format violation

		if (i) offset = -offset;

	}
	else {

		*err = 1;

		return 0;

	}

	if (*s) {

		*err = 1;

		return 0;

	}


	// And here comes the hard part --- there's no standard function to

	// convert struct tm containing UTC time into time_t without

	// messing global timezone settings (breaks multithreading and may

	// cause other problems) and thus we have to do this "by hand"

	//

	// NOTE: Overflow check does not detect too big overflows, but is

	// sufficient thanks to the fact that year numbers are limited to four

	// digit non-negative values.

	retval = t.tm_sec;

	retval += (t.tm_min - offset) * 60;

	retval += t.tm_hour * 3600;

	retval += (t.tm_mday - 1) * 86400;

	year = t.tm_year + 1900;

	if (sizeof(time_t) == 4) {

		// This is just to avoid too big overflows being undetected, finer

		// overflow detection is done below.

		if (year < 1900 || year > 2040) *err = 2;

	}

	// FIXME: Does POSIX really say, that all years divisible by 4 are

	// leap years (for consistency)??? Fortunately, this problem does

	// not exist for 32-bit time_t and we should'nt be worried about

	// this until the year of 2100 :)

	isleap = ((year % 4 == 0) && (year % 100 != 0)) || (year % 400 == 0);

	for (i = t.tm_mon - 1; i >= 0; --i) retval += days[isleap][i] * 86400;

	retval += (year - 1970) * 31536000;

	if (year < 1970) {

		retval -= ((1970 - year + 2) / 4) * 86400;

		if (sizeof(time_t) > 4) {

			for (i = 1900; i >= year; i -= 100) {

				if (i % 400 == 0) continue;

				retval += 86400;

			}

		}

		if (retval >= 0) *err = 2;

	}
	else {

		retval += ((year - 1970 + 1) / 4) * 86400;

		if (sizeof(time_t) > 4) {

			for (i = 2100; i < year; i += 100) {

				// The following condition is the reason to

				// start with 2100 instead of 2000

				if (i % 400 == 0) continue;

				retval -= 86400;

			}

		}

		if (retval < 0) *err = 2;

	}


	if (*err) retval = 0;

	return retval;

}

int CertificateItemParse::setCertificate(const unsigned char *pCert, unsigned int uiCertLen)
{
	if (m_pX509)
	{
		X509_free(m_pX509);
		m_pX509 = NULL;
	}

	m_pX509 = d2i_X509(NULL,&pCert, uiCertLen);

	if (m_pX509)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}


int CertificateItemParse::parse()
{
	int uiRet = -1;
	char data_value_tmp[BUFFER_LEN_1K] = {0};

	ASN1_INTEGER *asn1_i = NULL;
	BIGNUM *bignum = NULL;
	char *serial = NULL;

	char oid[128] = { 0 };
	ASN1_OBJECT* salg = NULL;

	ASN1_TIME *start = NULL;
	ASN1_TIME *end = NULL;

	if (m_pX509)
	{
		{
			m_iVersion = X509_get_version(m_pX509);
			switch (m_iVersion)
			{
			case 0:     //V1  
			case 1:     //V2  
			case 2:     //V3  
				m_iVersion += 1;
				break;
			default:
				//Error! 
				m_iVersion = -1;
				break;
			}
			memset(data_value_tmp, 0, sizeof(data_value_tmp));
			sprintf(data_value_tmp, "%d", m_iVersion);
			m_strVersion = std::string(data_value_tmp);
		}

		{
			asn1_i = X509_get_serialNumber(m_pX509);
			bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
			if (bignum == NULL)
			{
				goto err;
			}
			serial = BN_bn2hex(bignum);
			if (serial == NULL)
			{
				goto err;
			}
			
			memset(data_value_tmp, 0, sizeof(data_value_tmp));
			sprintf(data_value_tmp, "%s", serial);
			m_strSerialNumber = std::string(data_value_tmp);
		}

		{
			EVP_PKEY *pk = NULL;
			stack_st_X509* chain = NULL;
			X509_EXTENSION *pex = NULL;

			pk = X509_get_pubkey(m_pX509);
			if (!pk)
			{
				goto err;
			}

			if (EVP_PKEY_RSA == pk->type)
			{
				m_iKeyAlg = ECertificate_KEY_ALG_RSA;
			}
			else if (EVP_PKEY_EC == pk->type)
			{
				m_iKeyAlg = ECertificate_KEY_ALG_EC;
			}
			else if (EVP_PKEY_DSA == pk->type)
			{
				m_iKeyAlg = ECertificate_KEY_ALG_DSA;
			}
			else if (EVP_PKEY_DH == pk->type)
			{
				m_iKeyAlg = ECertificate_KEY_ALG_DH;
			}
			else
			{
				m_iKeyAlg = ECertificate_KEY_ALG_UNKNOW;
			}
		}

		{
			m_ulKeyUsage = m_pX509->ex_kusage;
		}

		{
			salg = m_pX509->sig_alg->algorithm;
			OBJ_obj2txt(oid, 128, salg, 1);
			
			if (0 == strcmp(CERT_SIGNATURE_ALG_SM3SM2, oid))
			{
				m_strOID = "SM3SM2";
			}
			else if (0 == strcmp(CERT_SIGNATURE_ALG_RSA_RSA, oid))
			{
				m_strOID = "RSA";
			}
			else if (0 == strcmp(CERT_SIGNATURE_ALG_SHA1RSA, oid))
			{
				m_strOID = "sha1RSA";
			}
			else if (0 == strcmp(CERT_SIGNATURE_ALG_MD2RSA, oid))
			{
				m_strOID = "md2RSA";
			}
			else if (0 == strcmp(CERT_SIGNATURE_ALG_MD5RSA, oid))
			{
				m_strOID = "md5RSA";
			}
			else if (0 == strcmp(CERT_SIGNATURE_ALG_SHA256RSA, oid))
			{
				m_strOID = "sha256RSA";
			}
			else 
			{
				m_strOID = "unknow";
			}
		}

		{
			X509_NAME *pCommonName = NULL;

			pCommonName = X509_get_issuer_name(m_pX509);
			if (!pCommonName)
			{
				goto err;
			}

			size_t len = i2d_X509_NAME(pCommonName, NULL);

			m_strIssue.resize(len);

			unsigned char * ptr_out = (unsigned char *)&m_strIssue.front();

			len = i2d_X509_NAME(pCommonName, &ptr_out);
		}

		{
			X509_NAME *pCommonName = NULL;

			pCommonName = X509_get_subject_name(m_pX509);
			if (!pCommonName)
			{
				goto err;
			}

			size_t len = i2d_X509_NAME(pCommonName, NULL);

			m_strSubject.resize(len);

			unsigned char * ptr_out = (unsigned char *)&m_strSubject.front();

			len = i2d_X509_NAME(pCommonName, &ptr_out);
		}

		{
			int err = 0;
			start = X509_get_notBefore(m_pX509);
			end = X509_get_notAfter(m_pX509);

			m_tNotBefore = ASN1_TIME_get(start, &err);
			m_tNotAfter = ASN1_TIME_get(end, &err);

			API_TimeToStringEX(m_strNotBefore,m_tNotBefore);
			API_TimeToStringEX(m_strNotAfter, m_tNotAfter);
		}

		{

			int i = 0;
			int crit = 0;

			AUTHORITY_KEYID *akeyid = NULL;

			akeyid = (AUTHORITY_KEYID*)X509_get_ext_d2i(m_pX509, NID_authority_key_identifier, &crit, NULL);

			if (akeyid)
			{
				memset(data_value_tmp, 0, sizeof(data_value_tmp));
				for (i = 0; i < akeyid->keyid->length; i++)
				{
					char keyid[8] = { 0 };
					sprintf(keyid, "%02x", akeyid->keyid->data[i]);
					strcat(data_value_tmp, keyid);
				}

				m_strIssueKeyID = std::string(data_value_tmp);
			}

		}

		{
			int i = 0;
			int crit = 0;

			ASN1_OCTET_STRING *akeyid = NULL;

			akeyid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(m_pX509, NID_subject_key_identifier, &crit, NULL);

			if (akeyid)
			{
				memset(data_value_tmp, 0, sizeof(data_value_tmp));
				for (i = 0; i < akeyid->length; i++)
				{
					char keyid[8] = { 0 };
					sprintf(keyid, "%02x", akeyid->data[i]);
					strcat(data_value_tmp, keyid);
				}

				m_strSubjectKeyID = std::string(data_value_tmp);
			}
		}

		uiRet = 0;
	}
	else
	{
		goto err;
	}
	

err:

	if (serial)
	{
		//free(serial);
	}

	if (bignum)
	{
		BN_free(bignum);
	}
	

	return uiRet;
}

