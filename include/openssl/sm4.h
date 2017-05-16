
// sms4.h
#ifndef _SMS4_H_111
#define _SMS4_H_111

#define SM4_MAXNR  14

#define SMS4_KEY_LEN		16

#define SMS4_BLOCK_LEN		16

#define SMS4_MAX_LEN		512

#define	NO_ERR				0
#define	PARAM_ERR			-1
#define DATA_LEN_ERR	-2

struct sm4_key_st {
#ifdef SM4_LONG
    unsigned long rd_key[4 *(SM4_MAXNR + 1)];
#else
    unsigned int rd_key[4 *(SM4_MAXNR + 1)];
#endif
    int rounds;
};
typedef struct sm4_key_st SM4_KEY;

#ifdef	__cplusplus
//extern "C" {
#endif


unsigned int tcm_sms4_encrypt(unsigned char *IV, unsigned char *input, unsigned int inputLen, unsigned char *output, unsigned char *key);

unsigned int tcm_sms4_decrypt(unsigned char *IV, unsigned char *input, unsigned int inputLen, unsigned char *output, unsigned char *key);

int SMS4EncryptECB(unsigned char *pbKey, unsigned char *pbInData, unsigned int uInDataLen, unsigned char *pbOutData);

int SMS4DecryptECB(unsigned char *pbKey, unsigned char *pbInData, unsigned int uInDataLen, unsigned char *pbOutData);

#ifdef	__cplusplus
//}
#endif



#endif
