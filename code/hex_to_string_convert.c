// 字符串转16进制
static int str_to_hex(char *dst,  int dst_len, const char *src, int src_len)
{
    if (dst_len <= (2 * src_len))
    {
        lerror("parameter invalid, dst_len: %d, src_len: %d", dst_len, src_len);
        return -1;
    }
    int i = 0;
    int len = 0;
    for( i = 0; i < src_len; i++ ) {
        len += snprintf(dst + len, HEX_MAX_SIZE + 1, "%02X", (unsigned char)src[i]);
    }
    return len;
}

// 16进制转字符串
static int hex_to_str(char *dst, int dst_len, const char *hex, int hex_len)
{
    if (hex_len > (2 * dst_len))
    {
        lerror("parameter invalid, dst_len: %d, hex_len: %d", dst_len, hex_len);
        return -1;
    }
    size_t lhex = strlen(hex);
    int lret = lhex / 2;
    int i = 0 ;
    int len = 0;
    char tmp_hex[HEX_FORMAT_MAX_SIZE + 1] = {'\0'};
    tmp_hex[0] = '0';
    tmp_hex[1] = 'X';

    unsigned char character;

    for( i = 0; i < lret; i++ ) {
        tmp_hex[2] = (unsigned char)hex[i * 2];
        tmp_hex[3] = (unsigned char)hex[i * 2 + 1];
        character = strtoul(tmp_hex, NULL, 16);
        dst[i] = character;
        len += 1;
    }
    return len;
}