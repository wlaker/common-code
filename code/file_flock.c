int file_lcok(const char* file)
{
	mode_t f_attrib = S_IRUSR | S_IWUSR | S_IROTH | S_IWOTH;
	int fd = open(file, O_RDONLY | O_CREAT, f_attrib);
	if (fd < 0) {
		lerror("open file(%s) failed :%s", SFGUARD_LOCK_FILE, strerror(errno));
		return -1;
	}

	if (flock(fd, LOCK_EX) < 0) {
		lerror("lock file(%s) failed: %s", SFGUARD_LOCK_FILE, strerror(errno));
		close(fd);
		fd = -1;
	}
	return fd;
}

void file_unlock(int fd)
{
	if (fd < 0)
	{
		return;
	}
	flock(fd, LOCK_UN);
	close(fd);
}
