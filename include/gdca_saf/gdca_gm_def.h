#ifndef _gdca_gm_def_h_
#define _gdca_gm_def_h_


#define SGD_MAX_PUBLICKEY_SIZE  256   //���Կ����
#define SGD_MAX_SYMMKEY_SIZE    256   //���Ự��Կ����

#define UNDEFINED               -1

#define GDCA_ALGO_RSA1024                 0
#define GDCA_ALGO_RSA2048                 10
#define GDCA_ALGO_SM2                     40


//ǩ���㷨
#define SGD_SM3_RSA              0x00010001     //����SM3�㷨��RSA�㷨��ǩ��
#define SGD_SHA1_RSA             0x00010002     //����SHA_1�㷨��RSA�㷨��ǩ��
#define SGD_SHA256_RSA           0x00010004     //����SHA_256�㷨��RSA�㷨��ǩ��
#define SGD_SM3_SM2              0x00020201     //����SM3�㷨��SM2�㷨��ǩ��

//���������㷨
#define SGD_SM1_ECB     0x00000101                //SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC     0x00000102                //SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB     0x00000104                //SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB     0x00000108                //SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC     0x00000110                //SM1�㷨MAC����

#define SGD_SSF33_ECB   0x00000201                //SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC   0x00000202                //SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB   0x00000204                //SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB   0x00000208                //SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC   0x00000210                //SSF33�㷨MAC����

#define SGD_SM4_ECB     0x00000401                //SM4�㷨ECB����ģʽ
#define SGD_SM4_CBC     0x00000402                //SM4�㷨CBC����ģʽ
#define SGD_SM4_CFB     0x00000404                //SM4�㷨CFB����ģʽ
#define SGD_SM4_OFB     0x00000408                //SM4�㷨OFB����ģʽ
#define SGD_SM4_MAC     0x00000410                //SM4�㷨MAC����

#define SGD_ZUC_EEA3    0x00000801                //ZUC���֮�������㷨128-EEA3�㷨
#define SGD_ZUC_EEI3    0x00000802                //ZUC���֮�������㷨128-EIA3�㷨

#define SGD_3DES_CBC    0x00002002                //3DES�㷨CBCģʽ

//�����Ӵ��㷨��ʶ
#define SGD_SM3         0x00000001                //
#define SGD_SHA1        0x00000002                //
#define SGD_SHA256      0x00000004                //


#define FT_CONFIG_FILE     "C:/CONFIG/saf_cfg.dat"
#define WATCH_CONFIG_FILE  "C:/CONFIG/saf_cfg_watch.dat"


//�û�����
typedef enum _UserType
{   
    UserAdmin  = 0,      //����Ա
    UserNormal = 1       //�û�
}UserType;

//��Կ��;
#define SGD_KEYUSAGE_SIGN         2    //ǩ��
#define SGD_KEYUSAGE_KEYEXCHANGE  3    //����

typedef enum _KeyUsage
{   
    KeyUsageEncrypt     = 1,    //����
    KeyUsageSign        = 2,    //ǩ��
    KeyUsageKeyExChange = 3     //��Կ����
}KeyUsage;

//��Կ����
typedef enum _KeyType
{   
    KeyTypeSM2     = 1,       //
    KeyTypeRSA1024 = 2,       //
    KeyTypeRSA2048 = 3,       //
    KeyTypeRSA3072 = 4,       //
    KeyTypeRSA4096 = 5
}KeyType;


#endif
