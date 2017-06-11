
#ifndef _OPENSSL_FUNC_DEF_H_
#define _OPENSSL_FUNC_DEF_H_

#include "o_all_type_def.h"

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	¹¦ÄÜÃû³Æ:	³õÊ¼»¯×ÊÔ´
	º¯ÊýÃû³Æ:	OpenSSL_Initialize
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:	
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	³õÊ¼»¯OPENSSL
	*/
	COMMON_API unsigned int OpenSSL_Initialize();

	/*
	¹¦ÄÜÃû³Æ:	ÊÍ·Å×ÊÔ´
	º¯ÊýÃû³Æ:	OpenSSL_Finalize
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:	
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÊÍ·Å×ÊÔ´
	*/
	COMMON_API unsigned int OpenSSL_Finalize();

	/*
	¹¦ÄÜÃû³Æ:	Éú³É¹«Ë½Ô¿¶Ô
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenKeys
	ÊäÈë²ÎÊý:	 
	Êä³ö²ÎÊý:	pbPublicKeyX		¹«Ô¿X
				pbPublicKeyY		¹«Ô¿Y
				pbPrivateKey		Ë½Ô¿
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³É¹«Ë½Ô¿¶Ô
	*/
	COMMON_API unsigned int OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉÖ¤ÊéÇëÇó
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenCSRWithPubkey
	ÊäÈë²ÎÊý:	pbPublicKeyX     ¹«Ô¿XÖµ
				uiPublicKeyXLen		¹«Ô¿X³¤¶È
				pbPublicKeyY     ¹«Ô¿YÖµ
				uiPublicKeyYLen		¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:	pbCSR		Ö¤ÊéÇëÇóÄÚÈÝ
				puiCSRLen		Ö¤ÊéÇëÇó³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉÖ¤ÊéÇëÇó
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	¹¦ÄÜÃû³Æ:	Éú³É¸ùÖ¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenRootCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÐÅÏ¢
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³É¸ùÖ¤Êé
	*/
	COMMON_API unsigned int OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉSM2Ö¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÄÚÈÝ
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉSM2Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉSM2Ö¤Êé(À©Õ¹£¬ÑéÖ¤²¢Ìæ»»Ö¤ÊéÇëÇóµÄ¹«Ô¿Ö®ºóÉú³ÉÖ¤Êé)
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÄÚÈÝ
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉSM2Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	¹¦ÄÜÃû³Æ:	Ö¤ÊéµõÏúÁÐ±í
	º¯ÊýÃû³Æ:	OpenSSL_SM2GenCRL
	ÊäÈë²ÎÊý:	pstCRLList				Ö¤ÊéµõÏúÄÚÈÝ
				uiCRLListSize			Ö¤Êé¸öÊý
				pbX509Cert			Ö¤ÊéÄÚÈÝ
				uiX509CertLen				Ö¤Êé³¤¶È
	Êä³ö²ÎÊý:   
				pbCRL				Ö¤ÊéµõÏúÁÐ±íÄÚÈÝ
				puiCRLLen				Ö¤ÊéµõÏúÁÐ±í³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Ö¤ÊéµõÏúÁÐ±í
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	¹¦ÄÜÃû³Æ:	¶ÔÖ¤Êé½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2SignCertWithKeys
	ÊäÈë²ÎÊý:	pbX509Cert					´ýÇ©ÃûÖ¤ÊéÄÚÈÝ
				uiX509CertLen				´ýÇ©ÃûÖ¤Êé³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbX509CertSigned				Ç©ÃûÖ¤ÊéÄÚÈÝ
				puiX509CertSignedLen			Ç©ÃûÖ¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÖ¤Êé½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔÖ¤ÊéÇëÇó½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2SignCSR
	ÊäÈë²ÎÊý:	pbCSR					´ýÇ©ÃûÖ¤ÊéÇëÇóÄÚÈÝ
				uiCSRLen					´ýÇ©ÃûÖ¤ÊéÇëÇó³¤¶È
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCSRSigned				Ç©ÃûÖ¤ÊéÇëÇóÄÚÈÝ
				puiCSRSignedLen			Ç©ÃûÖ¤ÊéÇëÇó³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÖ¤ÊéÇëÇó½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔCRL½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2SignCRL
	ÊäÈë²ÎÊý:	pbCRL					´ýÇ©ÃûCRLÄÚÈÝ
				uiCRLLen					´ýÇ©ÃûCRL³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔCRL½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔÏûÏ¢½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2SignMSG
	ÊäÈë²ÎÊý:	pbMSG						´ýÇ©ÃûÄÚÈÝ
				uiMSGLen					´ýÇ©Ãû³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÏûÏ¢½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	¹¦ÄÜÃû³Æ:	¶ÔHASH½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2SignMSG
	ÊäÈë²ÎÊý:	pbHash						´ýÇ©ÃûhashÄÚÈÝ
				uiHashLen					´ýÇ©Ãûhash³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔHASH½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
		);

	//X509½á¹¹ÄÚÈÝ
	typedef enum _X509_TYPE
	{
		X509_TYPE_CSR = 0,
		X509_TYPE_CERT = 1,
		X509_TYPE_CRL=2,
	}X509_TYPE;

	/*
	¹¦ÄÜÃû³Æ:	ÉèÖÃX509ÄÚÈÝµÄÇ©ÃûÖµ
	º¯ÊýÃû³Æ:	OpenSSL_SM2SetX509SignValue
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÉèÖÃX509ÄÚÈÝµÄÇ©ÃûÖµ
	*/
	COMMON_API unsigned int OpenSSL_SM2SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡X509ÄÚÈÝ£¨²»°üº¬Ç©ÃûÖµ£©
	º¯ÊýÃû³Æ:	OpenSSL_SM2SetX509SignValue
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	»ñÈ¡X509ÄÚÈÝ£¨²»°üº¬Ç©ÃûÖµ£©
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤SM2Ç©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2VerifyDigest
	ÊäÈë²ÎÊý:	pbHash		HASHÄÚÈÝ
				uiHashLen			HASH³¤¶È
				pbSig			Ç©ÃûÄÚÈÝ
				uiSigLen				Ç©Ãû³¤¶È
				pbPublicKeyX		¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen			¹«Ô¿X³¤¶È
				pbPublicKeyY		¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen			¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤SM2Ç©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤Ç©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_SM2VerifyMSG
	ÊäÈë²ÎÊý:	pbMSG				Ô­ÎÄÄÚÈÝ
				uiMSGLen					Ô­ÎÄ³¤¶È
				pbSig				Ç©ÃûÖµÄÚÈÝ
				uiSigLen					Ç©ÃûÖµ³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen				¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen				¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ç©Ãû
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤ÇëÇó
	º¯ÊýÃû³Æ:	OpenSSL_SM2VerifyCSR
	ÊäÈë²ÎÊý:	pbIN				ÇëÇóÄÚÈÝ
				uiINLen					ÇëÇó³¤¶È
				pbSig				Ç©ÃûÖµÄÚÈÝ
				uiSigLen					Ç©ÃûÖµ³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤ÇëÇó
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤Ö¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_SM2VerifyCert
	ÊäÈë²ÎÊý:	pbX509Cert			Ö¤ÊéÄÚÈÝ
				uiX509CertLen				Ö¤Êé³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen				¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen				¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤CRL
	º¯ÊýÃû³Æ:	OpenSSL_SM2VerifyCRL
	ÊäÈë²ÎÊý:	pbCRL					CRLÄÚÈÝ
				uiCRLLen				CRL³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen			¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen			¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡Ö¤ÊéÖ÷Ìâ
	º¯ÊýÃû³Æ:	OpenSSL_CertGetSubject
	ÊäÈë²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				uiX509CertLen		Ö¤Êé³¤¶È
	Êä³ö²ÎÊý:	pbSubject	Ö÷ÌâÄÚÈÝ
				puiSubjectLen		Ö÷Ìâ³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	»ñÈ¡Ö¤ÊéÖ÷Ìâ
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSubject, unsigned int * puiSubjectLen
		);

	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡Ö¤Êé¹«Ô¿
	º¯ÊýÃû³Æ:	OpenSSL_CertGetPubkey
	ÊäÈë²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				uiX509CertLen		Ö¤Êé³¤¶È
	Êä³ö²ÎÊý:	pbPublicKey	¹«Ô¿ÄÚÈÝ
				puiPublicKeyLen		¹«Ô¿³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	»ñÈ¡Ö¤Êé¹«Ô¿
	*/
	COMMON_API unsigned int OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);
		
	COMMON_API unsigned int OpenSSL_CsrGetPubkey(const unsigned char *pbCSR, unsigned int uiCSRLen,
	unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);


	/*
	»ñÈ¡Ö¤ÊéÐòÁÐºÅ
	*/
	COMMON_API unsigned int OpenSSL_CertGetSN(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSN, unsigned int * puiSNLen);

	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡Ö¤ÊéÖ÷ÌâÏî
	º¯ÊýÃû³Æ:	OpenSSL_CertGetSubjectItem
	ÊäÈë²ÎÊý:	
				pbX509Cert				Ö¤ÊéÄÚÈÝ
				uiX509CertLen			Ö¤Êé³¤¶È
				uiIndex					Ïî±êÊ¾
	Êä³ö²ÎÊý:   
				pbSubjectItem			ÏîÖµ
				puiSubjectItemLen		Ïî³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	»ñÈ¡Ö¤ÊéÖ÷ÌâÏî
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		int uiIndex, 
		unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen
		);

	/*
	¹¦ÄÜÃû³Æ:	SM2½âÃÜ
	*/
	COMMON_API unsigned int OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	¹¦ÄÜÃû³Æ:	SM2¼ÓÃÜ
	*/
	COMMON_API unsigned int OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤SM2µã
	*/
	COMMON_API unsigned int OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	¹¦ÄÜÃû³Æ:	¼ÓÃÜÄÚÈÝÊä³öÎÄ¼þ
	*/
	COMMON_API unsigned int OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned int uiINLen, 
		unsigned int uiType,
		char * szFileName,
		unsigned int fileEncode, char * szPassword
		);

	/*
	¹¦ÄÜÃû³Æ:	SM2½âÃÜ
	*/
	COMMON_API unsigned int OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	¹¦ÄÜÃû³Æ:	SM2¼ÓÃÜ
	*/
	COMMON_API unsigned int OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡Ö¤Êé¹«Ô¿Ëã·¨
	*/
	COMMON_API unsigned int OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned int *puiPublicKeyAlgorLen
		);

	/*
	¹¦ÄÜÃû³Æ:	±È½ÏÖ¤ÊéµÄ°ä·¢ÕßºÍÊ¹ÓÃÕß
	*/
	COMMON_API unsigned int OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned int * bEqual
		);

	COMMON_API unsigned int OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned int uiX509CertLen,int uiIndex, unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen);

	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////

#if defined(GM_ECC_512_SUPPORT)
	// GM_ECC_512 start
	/*
	¹¦ÄÜÃû³Æ:	Éú³É¹«Ë½Ô¿¶Ô
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenKeys
	ÊäÈë²ÎÊý:	 
	Êä³ö²ÎÊý:	pbPublicKeyX		¹«Ô¿X
				pbPublicKeyY		¹«Ô¿Y
				pbPrivateKey		Ë½Ô¿
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³É¹«Ë½Ô¿¶Ô
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉÖ¤ÊéÇëÇó
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenCSRWithPubkey
	ÊäÈë²ÎÊý:	pbPublicKeyX     ¹«Ô¿XÖµ
				uiPublicKeyXLen		¹«Ô¿X³¤¶È
				pbPublicKeyY     ¹«Ô¿YÖµ
				uiPublicKeyYLen		¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:	pbCSR		Ö¤ÊéÇëÇóÄÚÈÝ
				puiCSRLen		Ö¤ÊéÇëÇó³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉÖ¤ÊéÇëÇó
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	¹¦ÄÜÃû³Æ:	Éú³É¸ùÖ¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenRootCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÐÅÏ¢
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³É¸ùÖ¤Êé
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉGMECC512Ö¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÄÚÈÝ
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉGMECC512Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	¹¦ÄÜÃû³Æ:	Éú³ÉGMECC512Ö¤Êé(À©Õ¹£¬ÑéÖ¤²¢Ìæ»»Ö¤ÊéÇëÇóµÄ¹«Ô¿Ö®ºóÉú³ÉÖ¤Êé)
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenCert
	ÊäÈë²ÎÊý:	pbCSR		ÇëÇóÄÚÈÝ
				uiCSRLen			ÇëÇó³¤¶È
				uiSerialNumber	ÐòÁÐºÅ
				uiNotBefore		¿ªÊ¼Ê±¼ä
				uiNotAfter		½áÊøÊ±¼ä
	Êä³ö²ÎÊý:	pbX509Cert		Ö¤ÊéÄÚÈÝ
				puiX509CertLen		Ö¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Éú³ÉGMECC512Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	¹¦ÄÜÃû³Æ:	Ö¤ÊéµõÏúÁÐ±í
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512GenCRL
	ÊäÈë²ÎÊý:	pstCRLList				Ö¤ÊéµõÏúÄÚÈÝ
				uiCRLListSize			Ö¤Êé¸öÊý
				pbX509Cert			Ö¤ÊéÄÚÈÝ
				uiX509CertLen				Ö¤Êé³¤¶È
	Êä³ö²ÎÊý:   
				pbCRL				Ö¤ÊéµõÏúÁÐ±íÄÚÈÝ
				puiCRLLen				Ö¤ÊéµõÏúÁÐ±í³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	Ö¤ÊéµõÏúÁÐ±í
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	¹¦ÄÜÃû³Æ:	¶ÔÖ¤Êé½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SignCertWithKeys
	ÊäÈë²ÎÊý:	pbX509Cert					´ýÇ©ÃûÖ¤ÊéÄÚÈÝ
				uiX509CertLen				´ýÇ©ÃûÖ¤Êé³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbX509CertSigned				Ç©ÃûÖ¤ÊéÄÚÈÝ
				puiX509CertSignedLen			Ç©ÃûÖ¤Êé³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÖ¤Êé½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔÖ¤ÊéÇëÇó½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SignCSR
	ÊäÈë²ÎÊý:	pbCSR					´ýÇ©ÃûÖ¤ÊéÇëÇóÄÚÈÝ
				uiCSRLen					´ýÇ©ÃûÖ¤ÊéÇëÇó³¤¶È
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCSRSigned				Ç©ÃûÖ¤ÊéÇëÇóÄÚÈÝ
				puiCSRSignedLen			Ç©ÃûÖ¤ÊéÇëÇó³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÖ¤ÊéÇëÇó½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔCRL½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SignCRL
	ÊäÈë²ÎÊý:	pbCRL					´ýÇ©ÃûCRLÄÚÈÝ
				uiCRLLen					´ýÇ©ÃûCRL³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔCRL½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	¹¦ÄÜÃû³Æ:	¶ÔÏûÏ¢½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SignMSG
	ÊäÈë²ÎÊý:	pbMSG						´ýÇ©ÃûÄÚÈÝ
				uiMSGLen					´ýÇ©Ãû³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔÏûÏ¢½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	¹¦ÄÜÃû³Æ:	¶ÔHASH½øÐÐÇ©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SignMSG
	ÊäÈë²ÎÊý:	pbHash						´ýÇ©ÃûhashÄÚÈÝ
				uiHashLen					´ýÇ©Ãûhash³¤¶È
				pbPublicKeyX				Ç©ÃûÕß¹«Ô¿X
				pbPublicKeyY				Ç©ÃûÕß¹«Ô¿Y
				pbPrivateKey				Ë½Ô¿ÄÚÈÝ
				uiPrivateKeyLen				Ë½Ô¿³¤¶È
	Êä³ö²ÎÊý:   pbCRLSigned				Ç©ÃûCRLÄÚÈÝ
				puiCRLSignedLen			Ç©ÃûCRL³¤¶È
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	¶ÔHASH½øÐÐÇ©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
		);

	/*
	¹¦ÄÜÃû³Æ:	ÉèÖÃX509ÄÚÈÝµÄÇ©ÃûÖµ
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SetX509SignValue
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÉèÖÃX509ÄÚÈÝµÄÇ©ÃûÖµ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	¹¦ÄÜÃû³Æ:	»ñÈ¡X509ÄÚÈÝ£¨²»°üº¬Ç©ÃûÖµ£©
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512SetX509SignValue
	ÊäÈë²ÎÊý:	
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	»ñÈ¡X509ÄÚÈÝ£¨²»°üº¬Ç©ÃûÖµ£©
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤GMECC512Ç©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512VerifyDigest
	ÊäÈë²ÎÊý:	pbHash		HASHÄÚÈÝ
				uiHashLen			HASH³¤¶È
				pbSig			Ç©ÃûÄÚÈÝ
				uiSigLen				Ç©Ãû³¤¶È
				pbPublicKeyX		¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen			¹«Ô¿X³¤¶È
				pbPublicKeyY		¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen			¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤GMECC512Ç©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤Ç©Ãû
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512VerifyMSG
	ÊäÈë²ÎÊý:	pbMSG				Ô­ÎÄÄÚÈÝ
				uiMSGLen					Ô­ÎÄ³¤¶È
				pbSig				Ç©ÃûÖµÄÚÈÝ
				uiSigLen					Ç©ÃûÖµ³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen				¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen				¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ç©Ãû
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤ÇëÇó
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512VerifyCSR
	ÊäÈë²ÎÊý:	pbIN				ÇëÇóÄÚÈÝ
				uiINLen					ÇëÇó³¤¶È
				pbSig				Ç©ÃûÖµÄÚÈÝ
				uiSigLen					Ç©ÃûÖµ³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤ÇëÇó
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤Ö¤Êé
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512VerifyCert
	ÊäÈë²ÎÊý:	pbX509Cert			Ö¤ÊéÄÚÈÝ
				uiX509CertLen				Ö¤Êé³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen				¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen				¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤CRL
	º¯ÊýÃû³Æ:	OpenSSL_GMECC512VerifyCRL
	ÊäÈë²ÎÊý:	pbCRL					CRLÄÚÈÝ
				uiCRLLen				CRL³¤¶È
				pbPublicKeyX			¹«Ô¿XÄÚÈÝ
				uiPublicKeyXLen			¹«Ô¿X³¤¶È
				pbPublicKeyY			¹«Ô¿YÄÚÈÝ
				uiPublicKeyYLen			¹«Ô¿Y³¤¶È
	Êä³ö²ÎÊý:   
	·µ»ØÖµ:   
	Ê§°Ü£º
	¹¦ÄÜÃèÊö:	ÑéÖ¤Ö¤Êé
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	¹¦ÄÜÃû³Æ:	GMECC512½âÃÜ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	¹¦ÄÜÃû³Æ:	GMECC512¼ÓÃÜ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	¹¦ÄÜÃû³Æ:	ÑéÖ¤GMECC512µã
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);


	/*
	¹¦ÄÜÃû³Æ:	GMECC512½âÃÜ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	¹¦ÄÜÃû³Æ:	GMECC512¼ÓÃÜ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512EncryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512GenPFX(const char *password,const char *nickname, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char * pbX509CA, unsigned int uiX509CALen,
		int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
		unsigned char *pbPFX, unsigned int * puiPFXLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512GenExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512RestoreExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbOldPrivateKey, unsigned int uiOldPrivateKeyLen, 
		unsigned char *pbIN, unsigned int uiINLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	// GM_ECC_512 end 
#endif

#if defined(GM_ECC_512_SUPPORT_SKF)

	COMMON_API unsigned int SKF_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	COMMON_API unsigned int SKF_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);
#endif



	COMMON_API unsigned int OpenSSL_SM2GenPFX(const char *password,const char *nickname, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char * pbX509CA, unsigned int uiX509CALen,
		int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
		unsigned char *pbPFX, unsigned int * puiPFXLen
		);

	COMMON_API unsigned int OpenSSL_SM2GenExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_SM2RestoreExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbOldPrivateKey, unsigned int uiOldPrivateKeyLen, 
		unsigned char *pbIN, unsigned int uiINLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	typedef struct _OPST_CERT_LIST{
		unsigned char * content;
		int contentLen;
	}OPST_CERT_LIST;

	COMMON_API unsigned int OpenSSL_P7BMake(
		OPST_CERT_LIST pX509List[],
		int uiX509ListLen,
		const unsigned char *pbCRL, unsigned int uiCRLLen,
		unsigned char *pbP7BContent, unsigned int *puiP7BContentLen
		);

	COMMON_API unsigned int OpenSSL_VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char *pbX509CaCert, unsigned int uiX509CaCertLen
	);

	COMMON_API unsigned int OpenSSL_VerifyCertChain(
		unsigned char *pbX509Cert, unsigned int uiX509CertLen
	);

#ifdef __cplusplus
}
#endif


#endif /*_OPENSSL_FUNC_DEF_H_*/