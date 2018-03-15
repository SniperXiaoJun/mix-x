
// sm3.h
#ifndef _SM3_SOFT_H_
#define _SM3_SOFT_H_


#include <openssl/base.h>

#define  SM3_DIGEST_LEN     32

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int total[2];
	unsigned int state[8];
	unsigned char buffer[64];
} sch_context;

struct SM3ContextStr {
   sch_context context;
};

/*
 * 建立SM3 context
 * ctx SM3计算的上下文
 */
OPENSSL_EXPORT void tcm_sch_starts(sch_context *ctx );

/*
 * 提供输入数据
 * ctx SM3计算的上下文
 * input 输入数据
 * length 输入数据长度
 */
OPENSSL_EXPORT void tcm_sch_update( sch_context *ctx, unsigned char *input, unsigned int length);

/*
 * 计算结果
 * ctx SM3计算的上下文
 * digest 输出的Hash值
 */
OPENSSL_EXPORT void tcm_sch_finish( sch_context *ctx, unsigned char digest[32] );


/* 
 * 直接根据输入计算结果
 * datalen_in 输入数据长度
 * pdata_in 输入数据
 * digest 输出的Hash值
 */
OPENSSL_EXPORT int tcm_sch_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char digest[32]);


OPENSSL_EXPORT int tcm_hmac(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char digest[32]);

OPENSSL_EXPORT int tcm_kdf(/*out*/unsigned char *key, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);

OPENSSL_EXPORT void tcm_sch_finish_EndRaw( sch_context *ctx, unsigned char digest[32] ) ;

OPENSSL_EXPORT void tcm_sch_Transform(sch_context *ctx, unsigned char *data);

#ifdef __cplusplus
}
#endif

#endif /* sm3.h */
