
#undef NDEBUG

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

char *do_mmap(char *path, int *fd, off_t *size)
{
	int err;
	struct stat st;
	char *p;

	*fd = open(path, O_RDWR);
	assert(*fd >= 0);
	err = fstat(*fd, &st);
	assert(!err);
	*size = st.st_size;
	// fuse doesn't support writable + shared
	p = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, *fd, 0);
	assert(p != MAP_FAILED);

	return p;
}

int main(int argc, char *argv[])
{
	int err, fd1, fd2;
	char *p, *q;
	off_t size;
	ssize_t ssz;

	err = link(argv[1], argv[2]);
	assert(!err);

	p = do_mmap(argv[1], &fd1, &size);
	q = do_mmap(argv[2], &fd2, &size);
	assert(!memcmp(p, q, size));

	ssz = write(fd1, "a", 1);
	assert(ssz == 1);
	munmap(q, size);
//	close(fd2);
	system("cat f2");
	assert(!memcmp(p, q, size));
	ssz = write(fd2, "b", 1);
	assert(ssz == 1);
	assert(!memcmp(p, q, size));
	
	return 0;
}
