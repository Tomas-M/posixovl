#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, const char **argv)
{
	struct sockaddr_un sock1, sock2, sock_c;
	const char *path1, *path2;
	int fd1, fd2, fdc, ret;
	socklen_t socklen = sizeof(sock_c);
	char buf[80];

	if (argc < 3) {
		fprintf(stderr, "Usage: %s PATH1 PATH2\n", *argv);
		return EXIT_FAILURE;
	}

	path1 = argv[1];
	path2 = argv[2];
	if (strlen(path1) > sizeof(sock1.sun_path)) {
		fprintf(stderr, "%s: %s: %s\n",
		        *argv, path1, strerror(ENAMETOOLONG));
		return EXIT_FAILURE;
	}
	if (strlen(path2) > sizeof(sock2.sun_path)) {
		fprintf(stderr, "%s: %s: %s\n",
		        *argv, path2, strerror(ENAMETOOLONG));
		return EXIT_FAILURE;
	}

	fd1 = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd1 < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	fd2 = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (fd2 < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&sock1, 0, sizeof(sock1));
	memset(&sock2, 0, sizeof(sock2));
	memset(&sock_c, 0, sizeof(sock_c));
	sock1.sun_family = PF_LOCAL;
	sock2.sun_family = PF_LOCAL;
	strncpy(sock1.sun_path, path1, sizeof(sock1.sun_path));
	strncpy(sock2.sun_path, path2, sizeof(sock2.sun_path));
	if (bind(fd1, (const void *)&sock1, sizeof(sock1)) < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}
	if (bind(fd2, (const void *)&sock2, sizeof(sock2)) < 0) {
		perror("bind");
		return EXIT_FAILURE;
	}

	if (listen(fd1, SOMAXCONN) < 0) {
		perror("listen");
		return EXIT_FAILURE;
	}

	fcntl(fd1, F_SETFL, fcntl(fd1, F_GETFL) | O_NONBLOCK);

	if (connect(fd2, (const void *)&sock1, sizeof(sock1)) < 0) {
		perror("connect");
		return EXIT_FAILURE;
	}

	if ((fdc = accept(fd1, (void *)&sock_c, &socklen)) < 0) {
		perror("accept");
		return EXIT_FAILURE;
	}

	fcntl(fd2, F_SETFL, fcntl(fd2, F_GETFL) | O_NONBLOCK);
	fcntl(fdc, F_SETFL, fcntl(fdc, F_GETFL) | O_NONBLOCK);

	write(fdc, "Hello World\n", 12);
	ret = read(fd2, buf, 80);
	if (ret > 0)
		printf("%.*s", ret, buf);

	close(fdc);
	close(fd2);
	close(fd1);
	return EXIT_SUCCESS;
}
