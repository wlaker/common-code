#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
/**
 *@brief rsa������������
 *@para dst ���ܺ�����
 *@para str ��������
 *@para len �������ݳ���
 *@return 0���ɹ���-1��ʧ��
 */
int rsa_decrypt(char **dst, const char *str, const int len);

/**
 *@brief rsa������������
 *@para str ��������
 *@para len �������ݳ���
 *@return �ɹ�:���ؼ������ݳ��ȣ�ʧ�ܷ���-1
 */
int rsa_encrypt(char **dst, const char *str, const int len);

/**
 *@brief aes���ܽӿ�
 *@param src ����������
 *@param src_len ���������ݳ���
 *@param dst ���ܺ�����
 *@param dst_len ���ܺ����ݻ����С
 *@return 0:�ɹ���-1��ʧ��
 */
int aes_encrypt(char *src, int src_len, char *key, char *dst, int dst_len);

/**
 *@brief aes���ܽӿ�
 *@param src ����������
 *@param src_len ���������ݳ���
 *@param dst ���ܺ�����
 *@param dst_len ���ܺ����ݻ����С
 *@return 0:�ɹ���-1��ʧ��
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
    int rsa_len = 0; //�ֶμ������ݳ���
    int rsa_enc_data_len = 0; //Ĭ��ÿ�μ����������ݳ���
    int dst_enc_len = 0; //���ռ����������ݳ���
    int enc_times = 0; //�ܼ��ܴ���
    int has_enc_len = 0; //�Ѿ��������ݳ���
    int per_enc_len = 0; //�ֶμ���ʱÿ�μ������ĳ���
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

    //������ܴ���
    enc_times = src_len / rsa_enc_data_len;
    if (src_len % rsa_enc_data_len)
    {
        enc_times += 1;
    }

    //������ܺ����ݴ洢
    *dst = (char *)calloc(enc_times * rsa_len + 1, 1); //����enc_times�Σ�ÿ�μ������ݳ���rsa_len
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
            per_enc_len = src_len - has_enc_len; //�������ü������ݵĳ���(Ӧ�������һ�μ���)
        }
        enc_ret = RSA_public_encrypt(per_enc_len, (unsigned char*)(src + has_enc_len), \
            (unsigned char*)(*dst + dst_enc_len), p_rsa, RSA_PKCS1_PADDING);
        if (enc_ret < 0)
        {
            lerror("RSA_public_encrypt error: %s", ERR_error_string(ERR_get_error(), NULL));
            ERR_clear_error();
            goto _END;
        }
        has_enc_len += per_enc_len; //�Ѿ������������ݳ���
        dst_enc_len += rsa_len; //���ܺ���������ݳ���
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
    int rsa_dec_data_len = 0; //Ĭ��ÿ�ν��ܺ��������ݳ���
    int dst_dec_len = 0; //���ܺ��������ݳ���
    int has_dec_len = 0; //�Ѿ��������ĳ���
    int dec_times = 0; //���ܴ���
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
    //У��������ݳ��ȣ������Ȳ���rsa_len������������Ч�ļ�������
    if (src_len % rsa_len)
    {
        lerror("encrypted data invalid, encrypted data len: %d, rsa_len: %d\n", src_len, rsa_len);
        goto _END;
    }
    //������ܴ���
    dec_times = src_len / rsa_len;

    //����洢�������ݴ洢
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
