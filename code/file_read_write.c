#ifndef __SFG_FILE_H__
#define __SFG_FILE_H__

/**
 *@brief д���ݵ��ļ�
 *@brief file �ļ���
 *@para date ����
 *@para date_len ���ݳ���
 *@para mode �����ļ�ģʽ
  *@return 0���ɹ���-1��ʧ��
 */
int write_file(char* file, char* data, int data_len);

/**
 *@brief ��ȡ�ļ�������
 *@brief file �ļ���
 *@para date ��Ŷ�ȡ����
 *@para date_len ��Ŷ�ȡ���ݻ����С
 *@para mode �����ļ�ģʽ
  *@return ʧ�ܷ���-1,�ɹ����ض�ȡ�ļ����ݴ�С
 */
int read_file(char* file, char* buff, int buff_len);

#endif


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "sfg_file.h"

int write_file(char* file, char* data, int data_len)
{
	if (!file || !data || !data_len) {
		return -1;
	}

	int ret = 0;
	int write_size = 0;
	FILE *fp = fopen(file, "w+");
	if (!fp) {
		return -1;
	}

	write_size = fwrite(data, 1, data_len, fp);
	if (write_size != data_len) {
		ret = -1;
	}

	fclose(fp);
	fp = NULL;
	return ret;
}

int read_file(char* file, char* buff, int buff_len)
{
	if (!file || !buff || !buff_len) {
		return -1;
	}

	int ret = -1;
	int file_len = 0;
	FILE *fp = fopen(file, "r");
	if (!fp) {
		return -1;
	}

	fseek(fp, 0L, SEEK_END);
	file_len = ftell(fp);
	fseek(fp, 0L, SEEK_SET);
	if(file_len > buff_len) {
		goto __END;
	}

	int read_len = fread(buff, 1, file_len, fp);
	if (read_len != file_len) {
		goto __END;
	}

	ret = file_len;
__END:
	if (fp) {
		fclose(fp);
		fp = NULL;
	}
	return ret;
}