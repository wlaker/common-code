#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
/**
 *@brief rsa解密密文数据
 *@para dst 解密后明文
 *@para str 密文数据
 *@para len 密文数据长度
 *@return 0：成功，-1：失败
 */
int rsa_decrypt(char **dst, const char *str, const int len);

/**
 *@brief rsa加密密文数据
 *@para str 明文数据
 *@para len 明文数据长度
 *@return 成功:返回加密数据长度，失败返回-1
 */
int rsa_encrypt(char **dst, const char *str, const int len);

/**
 *@brief aes加密接口
 *@param src 待加密数据
 *@param src_len 待加密数据长度
 *@param dst 加密后数据
 *@param dst_len 加密后数据缓存大小
 *@return 0:成功，-1：失败
 */
int aes_encrypt(char *src, int src_len, char *key, char *dst, int dst_len);

/**
 *@brief aes解密接口
 *@param src 待解密数据
 *@param src_len 待解密数据长度
 *@param dst 解密后数据
 *@param dst_len 解密后数据缓存大小
 *@return 0:成功，-1：失败
 */
int aes_decrypt(char *src, int src_len, char *key, char *dst, int dst_len);

int aes_encrypt(char *src, int src_len, char *key, char *dst, int dst_len)
{
    if (!src || !src_len || !key || !dst)
    {
       lerror("parameter invalid");
       return -1;
    }
    if (dst_len < src_len)
    {
        lerror("aes encrypt dst buffer not enough");
        return -1;
    }
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char*)key, AES_CRYPT_BITS, &aes) < 0)
    {
        lerror("set aes encrypt key failed");
        ERR_clear_error();
        return -1;
    }

    int en_len = 0;
    while (en_len < src_len)
    {
        AES_encrypt((unsigned char*)(src + en_len), (unsigned char*)(dst + en_len), &aes);
        en_len += AES_BLOCK_SIZE;
    }
    return 0;
}

int aes_decrypt(char *src, int src_len, char *key, char *dst, int dst_len)
{
    if (!src || !src_len || !key || !dst)
    {
       lerror("parameter invalid");
       return -1;
    }
    if (dst_len < src_len)
    {
        lerror("aes encrypt dst buffer not enough");
        return -1;
    }
    if (src_len % AES_BLOCK_SIZE != 0)
    {
       lerror("aes encrypted input data length error, input data len: %d", src_len);
       return -1;
    }

    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char*)key, AES_CRYPT_BITS, &aes) < 0)
    {
        lerror("set aes encrypt key failed");
        ERR_clear_error();
        return -1;
    }

    int de_len = 0;
    while (de_len < src_len)
    {
        AES_decrypt((unsigned char*)(src + de_len), (unsigned char*)(dst + de_len), &aes);
        de_len += AES_BLOCK_SIZE;
    }
    return 0;
}


int rsa_encrypt(char **dst, const char *src, const int src_len)
{
    if (!src || !dst || *dst || src_len <= 0)
    {
        lerror("parameter invalid\n");
        return -1;
    }
    int ret = -1;
    RSA *p_rsa = NULL;
    FILE *fp = NULL;
    int rsa_len = 0; //分段加密数据长度
    int rsa_enc_data_len = 0; //默认每次加密明文数据长度
    int dst_enc_len = 0; //最终加密密文数据长度
    int enc_times = 0; //总加密次数
    int has_enc_len = 0; //已经加密数据长度
    int per_enc_len = 0; //分段加密时每次加密明文长度
    int enc_ret = 0;

    fp = fopen(RSAKEY_PATH, "r");
    if (!fp)
    {
        lerror("fopen %s error: %s", RSAKEY_PATH, strerror(errno));
        goto _END;
    }

    p_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (p_rsa == NULL)
    {
        lerror("read RSAPrivateKey error: %s", ERR_error_string(ERR_get_error(), NULL));
        ERR_clear_error();
        goto _END;
    }
    rsa_len = RSA_size(p_rsa);
    rsa_enc_data_len = rsa_len - RSA_2048BIT_PADDING;

    //计算加密次数
    enc_times = src_len / rsa_enc_data_len;
    if (src_len % rsa_enc_data_len)
    {
        enc_times += 1;
    }

    //分配加密后数据存储
    *dst = (char *)calloc(enc_times * rsa_len + 1, 1); //加密enc_times次，每次加密数据长度rsa_len
    if (!(*dst))
    {
        lerror("calloc mem error: %s", strerror(errno));
        goto _END;
    }

    has_enc_len = 0;
    per_enc_len = rsa_enc_data_len;
    while (has_enc_len < src_len)
    {
        if (src_len - has_enc_len < rsa_enc_data_len)
        {
            per_enc_len = src_len - has_enc_len; //重新设置加密数据的长度(应该是最后一次加密)
        }
        enc_ret = RSA_public_encrypt(per_enc_len, (unsigned char*)(src + has_enc_len), \
            (unsigned char*)(*dst + dst_enc_len), p_rsa, RSA_PKCS1_PADDING);
        if (enc_ret < 0)
        {
            lerror("RSA_public_encrypt error: %s", ERR_error_string(ERR_get_error(), NULL));
            ERR_clear_error();
            goto _END;
        }
        has_enc_len += per_enc_len; //已经加密明文数据长度
        dst_enc_len += rsa_len; //加密后的密文数据长度
    }
    ret = dst_enc_len;
_END:
    if(p_rsa)
    {
        RSA_free(p_rsa);
    }
    if(fp)
    {
        fclose(fp);
    }
    if (ret <= 0)
    {
        if (*dst)
        {
            free(*dst);
            *dst = NULL;
        }
    }
    return ret;
}

int rsa_decrypt(char **dst, const char *src, const int src_len)
{
    if (!src || !dst || *dst || src_len <= 0)
    {
        lerror("parameter invalid");
        return -1;
    }

    int ret = -1;
    RSA  *p_rsa = NULL;
    FILE *fp = NULL;
    int rsa_len = 0;
    int rsa_dec_data_len = 0; //默认每次解密后明文数据长度
    int dst_dec_len = 0; //解密后明文数据长度
    int has_dec_len = 0; //已经解密明文长度
    int dec_times = 0; //解密次数
    int dec_ret = 0;

    fp = fopen(RSAKEY_PATH, "r");
    if (!fp)
    {
        lerror("fopen %s error: %s\n", RSAKEY_PATH, strerror(errno));
        goto _END;
    }

    p_rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    if (p_rsa == NULL)
    {
        lerror("read RSAPrivateKey error: %s", ERR_error_string(ERR_get_error(), NULL));
        ERR_clear_error();
        goto _END;
    }

    rsa_len = RSA_size(p_rsa);
    rsa_dec_data_len = rsa_len - RSA_2048BIT_PADDING;
    //校验加密数据长度，若长度不是rsa_len整数倍则是无效的加密数据
    if (src_len % rsa_len)
    {
        lerror("encrypted data invalid, encrypted data len: %d, rsa_len: %d\n", src_len, rsa_len);
        goto _END;
    }
    //计算解密次数
    dec_times = src_len / rsa_len;

    //分配存储解密数据存储
    *dst = (char *)calloc(dec_times * rsa_dec_data_len + 1, 1);
    if (!(*dst))
    {
        lerror("calloc mem error: %s\n", strerror(errno));
        goto _END;
    }

    has_dec_len = 0;
    while (has_dec_len < src_len)
    {
        dec_ret = RSA_private_decrypt(rsa_len, (unsigned char*)(src + has_dec_len), \
            (unsigned char*)(*dst + dst_dec_len), p_rsa, RSA_PKCS1_PADDING);
        if ( dec_ret < 0)
        {
            lerror("RSA_private_decrypt error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            ERR_clear_error();
            goto _END;
        }
        has_dec_len += rsa_len;
        dst_dec_len += dec_ret;
    }
    ret = 0;
_END:
    if(p_rsa)
    {
        RSA_free(p_rsa);
    }
    if(fp)
    {
        fclose(fp);
    }
    if (ret != 0)
    {
        if (*dst)
        {
            free(*dst);
            *dst = NULL;
        }
    }
    return ret;
}
