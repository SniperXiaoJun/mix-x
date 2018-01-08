#ifndef _SM2_H
#define _SM2_H

#define SM2_BYTES_LEN			32

#ifdef __cplusplus
extern "C" {
#endif


OPENSSL_EXPORT int tcm_ecc_init();


OPENSSL_EXPORT int tcm_ecc_release();


OPENSSL_EXPORT int tcm_ecc_encrypt(unsigned char *plaintext, unsigned int uPlaintextLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *ciphertext, unsigned int *puCiphertextLen);


OPENSSL_EXPORT int tcm_ecc_decrypt(unsigned char *ciphertext, unsigned int uCiphertextLen, unsigned char *prikey, unsigned int uPrikeyLen, unsigned char *plaintext, unsigned int *puPlaintextLen);

OPENSSL_EXPORT int tcm_get_usrinfo_value(unsigned char *userID, unsigned int uUserIDLen, unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char digest[32]);

OPENSSL_EXPORT int tcm_get_message_hash(unsigned char *msg, unsigned int msgLen, unsigned char  *userID, unsigned int uUserIDLen, 
	unsigned char *pubkey, unsigned int uPubkeyLen, unsigned char *digest, unsigned int *puDigestLen);

OPENSSL_EXPORT int tcm_ecc_signature( unsigned char *digest, unsigned int uDigestLen, unsigned char *prikey, unsigned int uPrikeyLen, /*out*/unsigned char *sig, /*out*/unsigned int *puSigLen);

OPENSSL_EXPORT int tcm_ecc_verify(unsigned char *digest, unsigned int uDigestLen, unsigned char *sig, unsigned int uSigLen, unsigned char *pubkey, unsigned int uPubkeyLen);

OPENSSL_EXPORT int tcm_ecc_exchange(unsigned char fA, unsigned char prikey_A[32], unsigned char pubkey_A[65], unsigned char prikey_RA[32], unsigned char pubkey_RA[65],
	unsigned char pubkey_B[65], unsigned char pubkey_RB[65], unsigned char Za[32], unsigned char Zb[32], /*out*/unsigned char key[48],
	/*out*/unsigned char S1[32], /*out*/unsigned char Sa[32]);


// if success return 1, otherwise return 0.
OPENSSL_EXPORT unsigned char tcm_ecc_is_point_valid(unsigned char *point, unsigned int uPointLen);

// if success return 1, otherwise return 0.
OPENSSL_EXPORT unsigned char tcm_ecc_point_to_uncompressed(unsigned char *point, unsigned int uPointLen, unsigned char *uncompressedpoint, unsigned int *puUncompressedpointLen);


OPENSSL_EXPORT int tcm_ecc_genkey(unsigned char *prikey, unsigned int *puPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


OPENSSL_EXPORT int tcm_ecc_point_from_privatekey(const unsigned char *prikey, const unsigned int uPrikeyLen, unsigned char *pubkey, unsigned int *puPubkeyLen);


OPENSSL_EXPORT unsigned char tcm_ecc_is_key_match(const unsigned char *prikey, const unsigned int uPrikeyLen, const unsigned char *pubkey, const unsigned int uPubkeyLen);


OPENSSL_EXPORT int SM2EncryptAsn1Convert(unsigned char *pbX, int nXLen,
					  unsigned char *pbY, int nYLen,
					  unsigned char *pbC3, int nC3Len,
					  unsigned char *pbC2, int nC2Len,
						  unsigned char *pbOutDer, int *pOutDerLen);

OPENSSL_EXPORT int SM2SignAsn1Convert(unsigned char *pbR, int nRLen,
					   unsigned char *pbS, int nSLen,	
					   unsigned char *pbOutDer, int *pOutDerLen);

OPENSSL_EXPORT int SM2SignD2i(unsigned char *pbInDer, int nInDerLen,
			   unsigned char *pbOutRS, int *pnOutRSLen);

OPENSSL_EXPORT int SM2CryptD2i(unsigned char *pbInDer, int nInDerLen,
	unsigned char *pbOutCipher, int *pnOutCipherLen);


OPENSSL_EXPORT int SM2_EC_Sign(int type, const uint8_t *digest,
	size_t digest_len, uint8_t *sig,
	unsigned int *sig_len, EC_KEY *key);

OPENSSL_EXPORT int SM2_EC_Verify(int type, const uint8_t *digest,
	size_t digest_len, const uint8_t *sig,
	size_t sig_len, EC_KEY *key);

OPENSSL_EXPORT int SM2_EC_Verify_2(int type, const uint8_t *digest,
	size_t digest_len, const uint8_t *sig,
	size_t sig_len, EC_KEY *key);

OPENSSL_EXPORT int SM2_EVPKEY_Cacl_Z(int type, EVP_PKEY *pkey, unsigned char digest[32]);

#ifdef __cplusplus
}
#endif


#endif /* _SM2_H */
