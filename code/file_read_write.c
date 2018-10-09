#ifndef __SFG_FILE_H__
#define __SFG_FILE_H__

/**
 *@brief 写数据到文件
 *@brief file 文件名
 *@para date 数据
 *@para date_len 数据长度
 *@para mode 操作文件模式
  *@return 0：成功，-1：失败
 */
int write_file(char* file, char* data, int data_len);

/**
 *@brief 读取文件中数据
 *@brief file 文件名
 *@para date 存放读取数据
 *@para date_len 存放读取数据缓存大小
 *@para mode 操作文件模式
  *@return 失败返回-1,成功返回读取文件数据大小
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