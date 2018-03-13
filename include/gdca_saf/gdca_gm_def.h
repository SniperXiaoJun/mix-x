#ifndef _gdca_gm_def_h_
#define _gdca_gm_def_h_


#define SGD_MAX_PUBLICKEY_SIZE  256   //最大公钥长度
#define SGD_MAX_SYMMKEY_SIZE    256   //最大会话密钥长度

#define UNDEFINED               -1

#define GDCA_ALGO_RSA1024                 0
#define GDCA_ALGO_RSA2048                 10
#define GDCA_ALGO_SM2                     40


//签名算法
#define SGD_SM3_RSA              0x00010001     //基于SM3算法和RSA算法的签名
#define SGD_SHA1_RSA             0x00010002     //基于SHA_1算法和RSA算法的签名
#define SGD_SHA256_RSA           0x00010004     //基于SHA_256算法和RSA算法的签名
#define SGD_SM3_SM2              0x00020201     //基于SM3算法和SM2算法的签名

//分组密码算法
#define SGD_SM1_ECB     0x00000101                //SM1算法ECB加密模式
#define SGD_SM1_CBC     0x00000102                //SM1算法CBC加密模式
#define SGD_SM1_CFB     0x00000104                //SM1算法CFB加密模式
#define SGD_SM1_OFB     0x00000108                //SM1算法OFB加密模式
#define SGD_SM1_MAC     0x00000110                //SM1算法MAC运算

#define SGD_SSF33_ECB   0x00000201                //SSF33算法ECB加密模式
#define SGD_SSF33_CBC   0x00000202                //SSF33算法CBC加密模式
#define SGD_SSF33_CFB   0x00000204                //SSF33算法CFB加密模式
#define SGD_SSF33_OFB   0x00000208                //SSF33算法OFB加密模式
#define SGD_SSF33_MAC   0x00000210                //SSF33算法MAC运算

#define SGD_SM4_ECB     0x00000401                //SM4算法ECB加密模式
#define SGD_SM4_CBC     0x00000402                //SM4算法CBC加密模式
#define SGD_SM4_CFB     0x00000404                //SM4算法CFB加密模式
#define SGD_SM4_OFB     0x00000408                //SM4算法OFB加密模式
#define SGD_SM4_MAC     0x00000410                //SM4算法MAC运算

#define SGD_ZUC_EEA3    0x00000801                //ZUC祖冲之机密性算法128-EEA3算法
#define SGD_ZUC_EEI3    0x00000802                //ZUC祖冲之机密性算法128-EIA3算法

#define SGD_3DES_CBC    0x00002002                //3DES算法CBC模式

//密码杂凑算法标识
#define SGD_SM3         0x00000001                //
#define SGD_SHA1        0x00000002                //
#define SGD_SHA256      0x00000004                //


#define FT_CONFIG_FILE     "C:/CONFIG/saf_cfg.dat"
#define WATCH_CONFIG_FILE  "C:/CONFIG/saf_cfg_watch.dat"


//用户类型
typedef enum _UserType
{   
    UserAdmin  = 0,      //管理员
    UserNormal = 1       //用户
}UserType;

//密钥用途
#define SGD_KEYUSAGE_SIGN         2    //签名
#define SGD_KEYUSAGE_KEYEXCHANGE  3    //加密

typedef enum _KeyUsage
{   
    KeyUsageEncrypt     = 1,    //加密
    KeyUsageSign        = 2,    //签名
    KeyUsageKeyExChange = 3     //密钥交换
}KeyUsage;

//密钥类型
typedef enum _KeyType
{   
    KeyTypeSM2     = 1,       //
    KeyTypeRSA1024 = 2,       //
    KeyTypeRSA2048 = 3,       //
    KeyTypeRSA3072 = 4,       //
    KeyTypeRSA4096 = 5
}KeyType;


#endif
