/*
 *	vfat-x - VFAT with Linux extensions
 *
 *	Copyright © Jan Engelhardt <jengelh@computergmbh.de>, 2007
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#define _ATFILE_SOURCE 1
#define _GNU_SOURCE 1
#define FUSE_USE_VERSION 26
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifndef S_IRUGO
#	define S_IRUGO (S_IRUSR | S_IRGRP | S_IROTH)
#	define S_IWUGO (S_IWUSR | S_IWGRP | S_IWOTH)
#	define S_IXUGO (S_IXUSR | S_IXGRP | S_IXOTH)
#endif
#ifndef S_IRWXUGO
#	define S_IRWXUGO (S_IRUGO | S_IWUGO | S_IXUGO)
#endif

#define static_cast(type, x) ((type)(x))

/* GLIBC device number handling. From ttyrpld. */
#define COMPAT_MAJOR(dev) \
	static_cast(unsigned long, ((dev) & 0xFFF00) >> 8)
#define COMPAT_MINOR(dev) \
	static_cast(unsigned long, ((dev) & 0xFF) | \
	(((dev) & 0xFFF00000) >> 12))
#define COMPAT_MKDEV(major, minor) \
	static_cast(unsigned long, ((minor) & 0xFF) | \
	(((minor) & 0xFFF00) << 12) | (((major) & 0xFFF) << 8))

/* Filename transformations */

/* Buggers */
#define should_not_happen() \
	do { \
		fprintf(stderr, "Should never happen! %s:%u\n", \
		        __FILE__, __LINE__); \
		abort(); \
	} while (0);
#define hcb_got_busted(path) \
	fprintf(stderr, "HCB %s got busted\n", (path))

/* Shortcut */
#define XRET(v) \
	return ({ \
		int __ret = (v); \
		(__ret >= 0) ? __ret : -errno; \
	})

/* Definitions */
struct hcb {
	char buf[PATH_MAX], tbuf[PATH_MAX];
	char *s_mode, *s_uid, *s_gid, *s_rdev, *s_target;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	dev_t rdev;
	size_t size;
};

/* Global */
static const char *root_dir;
static int root_fd;
static pthread_mutex_t vfatx_protect = PTHREAD_MUTEX_INITIALIZER;

static inline int lock_read(int fd)
{
	struct flock fl = {
		.l_type   = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	return fcntl(fd, F_SETLK, &fl);
}

static inline int lock_write(int fd)
{
	struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	return fcntl(fd, F_SETLK, &fl);
}

static __attribute__((pure)) const char *at(const char *in)
{
	if (*in != '/')
		should_not_happen();
	if (in[1] == '\0')
		return ".";
	return in + 1;
}

/*
 * __real_to_hcb - build the hidden control block (HCB) path from a real path
 */
static int __real_to_hcb(char *dest, size_t destsize, const char *src)
{
	const char *directory_part = src;
	const char *filename_part;
	struct stat sb;
	int ret;

	/*
	 * !S_ISDIR: @src is "/foo/bar"
	 *           => @dest must be "/foo/.vfatx.bar"
	 *  S_ISDIR: @src is "/foo/bar"
	 *           => @dest must be "/foo/bar/.vfatx."
	 */
	ret = fstatat(root_fd, at(src), &sb, AT_SYMLINK_NOFOLLOW);
	if (ret == 0 && S_ISDIR(sb.st_mode)) {
		ret = snprintf(dest, destsize, "%s/.vfatx.", src);
		if (ret > destsize)
			return -ENAMETOOLONG;
		return 0;
	}

	filename_part = strrchr(src, '/');
	if (filename_part++ == NULL)
		should_not_happen();

	ret = snprintf(dest, destsize, "%.*s.vfatx.%s",
	      filename_part - directory_part, directory_part,
	      filename_part);
	if (ret > destsize)
		return -ENAMETOOLONG;
	return 0;
}

#define real_to_hcb(dest, src) \
	__real_to_hcb((dest), sizeof(dest), (src))

static int hcb_read(const char *path, struct hcb *info, int fd)
{
	char *toul_ptr = NULL;
	ssize_t ret;

	if ((ret = read(fd, info->buf, sizeof(info->buf) - 1)) < 0)
		return -errno;
	info->buf[ret] = '\0';
	if (ret == 0)
		return -ENOENT;
	info->size   = ret;
	info->s_mode = info->buf;
	info->s_uid  = strchr(info->buf, ' ');
	if (info->s_uid++ == NULL)
		goto busted;
	info->s_gid = strchr(info->s_uid, ' ');
	if (info->s_gid++ == NULL)
		goto busted;
	info->s_rdev = strchr(info->s_gid, ' ');
	if (info->s_rdev++ == NULL)
		goto busted;
	info->s_target = strchr(info->s_rdev, ' ');
	if (info->s_target++ == NULL)
		goto busted;

	info->mode = strtoul(info->s_mode, NULL, 8);
	info->uid  = strtoul(info->s_uid, NULL, 0);
	info->gid  = strtoul(info->s_gid, NULL, 0);

	info->rdev = strtoul(info->s_rdev, &toul_ptr, 0);
	if (toul_ptr == NULL || *toul_ptr != ':')
		goto busted;
	++toul_ptr;
	info->rdev = COMPAT_MKDEV(info->rdev, strtoul(toul_ptr, NULL, 0));

	return 0;

 busted:
	hcb_got_busted(path);
	unlinkat(root_fd, at(path), 0);
	return -EINVAL;
}

static int hcb_write(const char *path, struct hcb *info, int fd)
{
	size_t z;
	int ret;

	lseek(fd, 0, SEEK_SET);
	ftruncate(fd, 0);
	ret = snprintf(info->buf, sizeof(info->buf), "%o %lu %lu %lu:%lu %s",
	      info->mode, static_cast(unsigned long, info->uid),
	      static_cast(unsigned long, info->gid), COMPAT_MAJOR(info->rdev),
	      COMPAT_MINOR(info->rdev), info->tbuf);
	if (ret >= sizeof(info->buf))
		return -EIO;

	z = strlen(info->buf);
	ret = write(fd, info->buf, z);
	if (ret < 0)
		return -errno;
	if (ret != z) {
		hcb_got_busted(path);
		unlinkat(root_fd, at(path), 0);
		return -EIO;
	}
	return 0;
}

static int hcb_lookup(const char *path, struct hcb *info)
{
	int fd, ret;

	fd = openat(root_fd, at(path), O_RDONLY);
	if (fd < 0)
		return -errno;
	if (lock_read(fd) < 0)
		return -errno;
	ret = hcb_read(path, info, fd);
	close(fd);
	return ret;
}

/*
 * wd_hcb_lookup -
 * @dir:	working directory
 * @name:	file
 * @info:	
 *
 * Combines the working directory @dir with @name (to form an absolute path)
 * then calls hcb_lookup().
 */
static inline int wd_hcb_lookup(const char *dir, const char *name,
    struct hcb *info)
{
	char path[PATH_MAX];
	int ret;
	ret = snprintf(path, sizeof(path), "%s%s", dir, name);
	if (ret >= sizeof(path))
		return -ENAMETOOLONG;
	return hcb_lookup(path, info);
}

/*
 * wd_real_hcb_lookup -
 * @dir:	working directory
 * @name:	file
 * @info:	
 *
 * Combines the working directory @dir with @name (to form an absolute path),
 * transforms it into the HCB filename, then calls hcb_lookup().
 */
static inline int wd_real_hcb_lookup(const char *dir, const char *name,
    struct hcb *info)
{
	char path[PATH_MAX], spec_path[PATH_MAX];
	int ret;
	ret = snprintf(path, sizeof(path), "%s%s", dir, name);
	if (ret >= sizeof(path))
		return -ENAMETOOLONG;
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;
	return hcb_lookup(spec_path, info);
}

static int hcb_init(const char *path, mode_t mode, uid_t uid,
    gid_t gid, dev_t rdev, const char *target, unsigned int flags)
{
	struct hcb info;
	char spec_path[PATH_MAX];
	int fd, ret;

	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;

	fd = openat(root_fd, at(spec_path), O_RDWR | O_CREAT | flags,
	     S_IRUGO | S_IWUSR);
	if (fd < 0)
		return -errno;
	if (lock_write(fd) < 0)
		return -errno;
	ret = hcb_read(spec_path, &info, fd);
	if (ret == -ENOENT) {
		const struct fuse_context *ctx = fuse_get_context();
		info.mode   = mode; /* is always specified then */
		info.uid    = ctx->uid;
		info.gid    = ctx->gid;
		info.rdev   = 0;
		*info.tbuf  = '\0';
	} else if (ret < 0) {
		goto err;
	}

	/* update */
	if (mode != -1)
		info.mode = mode;
	if (uid != -1)
		info.uid = uid;
	if (gid != -1)
		info.gid = gid;
	if (rdev != -1)
		info.rdev = rdev;
	if (target != NULL) {
		memset(info.tbuf, 0, sizeof(info.tbuf));
		strncpy(info.tbuf, target, sizeof(info.tbuf));
	}

	/* write out */
	ret = hcb_write(spec_path, &info, fd);
 err:
	close(fd);
	return ret;
}

static unsigned int is_hcb(const char *path)
{
	const char *file = strrchr(path, '/');
	if (file++ == NULL)
		should_not_happen();
	return strncmp(file, ".vfatx.", 7) == 0;
}

static int generic_permission(struct hcb *info, unsigned int mask)
{
	const struct fuse_context *ctx = fuse_get_context();
	mode_t mode = info->mode;

	if (ctx->uid == info->uid)
		mode >>= 6;
	else if (ctx->gid == info->gid)
		/* not right yet, should be in_group() */
		mode >>= 3;

	return ((mode & mask & (R_OK | W_OK | X_OK)) == mask) ? 0 : -EACCES;
}

static int vfatx_access(const char *path, int mode)
{
	char spec_path[PATH_MAX];
	struct hcb info;
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;

	ret = hcb_lookup(spec_path, &info);
	if (ret == -ENOENT) {
		/* No HCB, try real file */
		XRET(faccessat(root_fd, at(path), mode, AT_SYMLINK_NOFOLLOW));
	} else if (ret < 0) {
		return ret;
	}

	return generic_permission(&info, mode);
}

static int vfatx_chmod(const char *path, mode_t mode)
{
	if (is_hcb(path))
		return -ENOENT;
	return hcb_init(path, mode, -1, -1, -1, NULL, 0);
}

static int vfatx_chown(const char *path, uid_t uid, gid_t gid)
{
	if (is_hcb(path))
		return -ENOENT;
	return hcb_init(path, -1, uid, gid, -1, NULL, 0);
}

static int vfatx_close(const char *path, struct fuse_file_info *filp)
{
	XRET(close(filp->fh));
}

static inline unsigned int could_be_too_long(const char *path)
{
	/* Longest possible case is S_ISDIR: /root/path/.vfatx. */
	return strlen(root_dir) + strlen(path) +
	       sizeof("/.vfatx.") - 1 >= PATH_MAX;
}

static int vfatx_create(const char *path, mode_t mode,
    struct fuse_file_info *filp)
{
	int fd;

	if (is_hcb(path))
		return -EINVAL;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	fd = openat(root_fd, at(path), filp->flags, mode);
	if (fd < 0)
		return -errno;

	filp->fh = fd;
	return 0;
}

static int vfatx_ftruncate(const char *path, off_t length,
    struct fuse_file_info *filp)
{
	XRET(ftruncate(filp->fh, length));
}

static int vfatx_getattr(const char *path, struct stat *sb)
{
	struct hcb info;
	char spec_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;

	if (fstatat(root_fd, at(path), sb, AT_SYMLINK_NOFOLLOW) == 0) {
		/* Real file exists... */

		if (!S_ISDIR(sb->st_mode))
			/*
			 * Files by default start without an +x bit in vfat-x.
			 * (No pun intended.)
			 */
			sb->st_mode &= ~S_IXUGO;

		if ((ret = real_to_hcb(spec_path, path)) < 0)
			return ret;
		ret = hcb_lookup(spec_path, &info);
		if (ret == -ENOENT || ret == -EACCES)
			return 0;
		if (ret < 0)
			return ret;

		/* HCB also exists, update attributes. */
		sb->st_mode = info.mode;
		sb->st_uid  = info.uid;
		sb->st_gid  = info.gid;
		sb->st_rdev = info.rdev;
		return 0;
	}

	/* No real file, just a HCB. */
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;
	ret = hcb_lookup(spec_path, &info);
	if (ret < 0)
		return ret;

	sb->st_mode    = info.mode;
	sb->st_nlink   = 1;
	sb->st_uid     = info.uid;
	sb->st_gid     = info.gid;
	sb->st_rdev    = info.rdev;
	sb->st_size    = info.size;
	sb->st_blksize = 4096;
	sb->st_atime   =
	sb->st_ctime   =
	sb->st_mtime   = time(NULL);
	return 0;
}

static int vfatx_fgetattr(const char *path, struct stat *sb,
    struct fuse_file_info *filp)
{
	/*
	 * Need to use the normal getattr because we need to check for the
	 * HCB too, not just @filp->fh.
	 */
	return vfatx_getattr(path, sb);
}

static void *vfatx_init(struct fuse_conn_info *conn)
{
	/*
	 * There is no fopendirat(), we need to use fchdir() and
	 * opendir(relative_path) instead.
	 */
	if (fchdir(root_fd) < 0)
		abort();
	return NULL;
}

static int vfatx_lock(const char *path, struct fuse_file_info *filp, int cmd,
    struct flock *fl)
{
	XRET(fcntl(filp->fh, cmd, fl));
}

static int vfatx_mkdir(const char *path, mode_t mode)
{
	if (is_hcb(path))
		return -EINVAL;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;
	XRET(mkdirat(root_fd, at(path), mode));
}

static int vfatx_mknod(const char *path, mode_t mode, dev_t rdev)
{
	if (is_hcb(path))
		return -EINVAL;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	return hcb_init(path, mode, -1, -1, rdev, NULL, O_EXCL);
}

static int vfatx_open(const char *path, struct fuse_file_info *filp)
{
	int fd;

	if (is_hcb(path))
		return -ENOENT;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;
	/* no need to handle symlinks -- fuse seems to do that for us */
	if ((fd = openat(root_fd, at(path), filp->flags)) < 0)
		return -errno;

	filp->fh = fd;
	return 0;
}

static int vfatx_read(const char *path, char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	lseek(filp->fh, offset, SEEK_SET);
	XRET(read(filp->fh, buffer, size));
}

static int vfatx_readdir(const char *path, void *buffer,
    fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *filp)
{
	struct hcb info;
	struct dirent *dentry;
	struct stat sb;
	char *d_name;
	DIR *ptr;
	int ret = 0;

	if (is_hcb(path))
		return -ENOENT;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;
	/*
	 * Current working directory is root_fd (per vfatx_init()).
	 * Let's hope opendir(relative_path) works.
	 */
	if ((ptr = opendir(at(path))) == NULL)
		return -errno;

	memset(&sb, 0, sizeof(sb));
	while ((dentry = readdir(ptr)) != NULL) {
		sb.st_ino = dentry->d_ino;
		if (strncmp(dentry->d_name, ".vfatx.", 7) == 0) {
			/*
			 * If a HCB is found, return its real name, but return
			 * the attributes stored in the HCB.
			 */
			ret = wd_hcb_lookup(path, dentry->d_name, &info);
			if (ret < 0) {
				closedir(ptr);
				return ret;
			}
			sb.st_mode = info.mode;
			d_name     = dentry->d_name + 7;
		} else {
			/*
			 * Seen regular file.
			 */
			ret = wd_real_hcb_lookup(path,
			      dentry->d_name, &info);
			if (ret == 0 && !S_ISDIR(sb.st_mode))
				/*
				 * Real file, which has got a HCB - skip this
				 * entry. (Will be reading it in the other
				 * else case.)
				 */
				continue;
			if (ret < 0 && ret != -ENOENT && ret != -EACCES)
				return ret;

			sb.st_mode = ((unsigned long)dentry->d_type << 12);
			d_name     = dentry->d_name;

			if (!S_ISDIR(sb.st_mode))
				/*
				 * As usual, non-directories start without +x
				 */
				sb.st_mode &= ~S_IXUGO;
		}
		if (filldir(buffer, d_name, &sb, 0) > 0)
			break;
	}

	closedir(ptr);
	return 0;
}

static int vfatx_readlink(const char *path, char *dest, size_t size)
{
	struct hcb info;
	char spec_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;
	ret = hcb_lookup(spec_path, &info);
	if (ret < 0)
		return ret;
	if ((info.mode & S_IFMT) != S_IFLNK)
		return -EINVAL; /* not a symbolic link */

	memset(dest, 0, size);
	strncpy(dest, info.s_target, size - 1);
	return 0;
}

static int vfatx_rename(const char *oldpath, const char *newpath)
{
	char spec_oldpath[PATH_MAX], spec_newpath[PATH_MAX];
	struct hcb info;
	int ret, ret_1, ret_2;
	struct stat sb;

	if (is_hcb(oldpath))
		return -ENOENT;
	if (is_hcb(newpath))
		return -EINVAL;
	if (could_be_too_long(oldpath) || could_be_too_long(newpath))
		return -ENAMETOOLONG;

	/* We do not check for a real file until fstatat(). */
	if ((ret = real_to_hcb(spec_oldpath, oldpath)) < 0)
		return ret;
	ret = hcb_lookup(spec_oldpath, &info);
	if (ret == -ENOENT)
		/*
		 * No HCB. Existence of real oldfile unknown,
		 * but does not matter here.
		 */
		XRET(renameat(root_fd, at(oldpath), root_fd, at(newpath)));
	if (ret < 0)
		return ret;

	/* HCB exists. */
	if ((ret = real_to_hcb(spec_newpath, newpath)) < 0)
		return ret;
	ret = fstatat(root_fd, at(oldpath), &sb, AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		if (errno == ENOENT)
			/*
			 * Old HCB exists, real oldfile not, also simple.
			 */
			XRET(renameat(root_fd, at(spec_oldpath),
			              root_fd, at(spec_newpath)));
		else
			return -errno;
	}

	/* Real oldfile _and_ an old HCB. Needs special locking. */
	pthread_mutex_lock(&vfatx_protect);
	ret_1 = renameat(root_fd, at(oldpath), root_fd, at(newpath));
	if (ret_1 < 0) {
		pthread_mutex_unlock(&vfatx_protect);
		return -errno;
	}
	ret_2 = renameat(root_fd, at(spec_oldpath), root_fd, at(spec_newpath));
	if (ret_2 < 0) {
		/* !@#$%^& - error. Need to rename old file back. */
		ret = -errno;
		if (renameat(root_fd, at(newpath), root_fd, at(oldpath)) < 0)
			/* Even that failed. Keep new name, but kill HCB. */
			unlinkat(root_fd, at(spec_oldpath), 0);

		pthread_mutex_unlock(&vfatx_protect);
		return ret;
	}

	pthread_mutex_unlock(&vfatx_protect);
	return 0;
}

static int vfatx_rmdir(const char *path)
{
	char spec_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;

	if (unlinkat(root_fd, spec_path, 0) < 0 && errno != ENOENT)
		return -errno;
	XRET(unlinkat(root_fd, at(path), AT_REMOVEDIR));
}

static int vfatx_statfs(const char *path, struct statvfs *sb)
{
	if (fstatvfs(root_fd, sb) < 0)
		return -errno;
	sb->f_fsid = 0;
	return 0;
}

static int vfatx_symlink(const char *oldpath, const char *newpath)
{
	if (is_hcb(newpath))
		return -EINVAL;
	if (could_be_too_long(newpath))
		return -ENAMETOOLONG;
	return hcb_init(newpath, S_IFLNK | S_IRWXUGO, -1, -1, -1,
	       oldpath, O_EXCL);
}

static int vfatx_truncate(const char *path, off_t length)
{
	char spec_path[PATH_MAX];
	struct hcb info;
	int fd, ret;

	if (is_hcb(path))
		return -ENOENT;

	/*
	 * There is no ftruncateat(), so need to use openat()+ftruncate() here.
	 */
	fd = openat(root_fd, at(path), 0, O_WRONLY);
	if (fd < 0 && errno == ENOENT) {
		/* No real file */
		if ((ret = real_to_hcb(spec_path, path)) < 0)
			return ret;
		ret = hcb_lookup(spec_path, &info);
		if (ret < 0)
			return ret;
		/*
		 * A HCB was found. But truncating special
		 * files (e.g. /dev/null) returns -EINVAL.
		 */
		return -EINVAL;
	} else if (fd < 0) {
		return -errno;
	}

	ret = ftruncate(fd, length);
	if (ret < 0)
		ret = -errno;

	close(fd);
	return ret;
}

static int vfatx_unlink(const char *path)
{
	char spec_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(spec_path, path)) < 0)
		return ret;

	/* Ignore if HCB not found */
	if (unlinkat(root_fd, at(spec_path), 0) < 0 && errno != ENOENT)
		return -errno;
	XRET(unlinkat(root_fd, at(path), 0));
}

static int vfatx_utimens(const char *path, const struct timespec *ts)
{
	char spec_path[PATH_MAX], real_path[PATH_MAX];
	struct timeval tv;
	int ret;

	if (is_hcb(path))
		return -ENOENT;

	tv.tv_sec  = ts->tv_sec;
	tv.tv_usec = ts->tv_nsec / 1000;

	ret = futimesat(root_fd, at(real_path), &tv);
	if (ret < 0 && errno == ENOENT) {
		/* See if there is a HCB */
		if ((ret = real_to_hcb(spec_path, path)) < 0)
			return ret;
		ret = futimesat(root_fd, at(spec_path), &tv);
	}

	XRET(ret);
}

static int vfatx_write(const char *path, const char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	lseek(filp->fh, offset, SEEK_SET);
	XRET(write(filp->fh, buffer, size));
}

static const struct fuse_operations vfatx_ops = {
	.access     = vfatx_access,
	.chmod      = vfatx_chmod,
	.chown      = vfatx_chown,
	.create     = vfatx_create,
	.fgetattr   = vfatx_fgetattr,
	.ftruncate  = vfatx_ftruncate,
	.getattr    = vfatx_getattr,
	.init       = vfatx_init,
	.lock       = vfatx_lock,
	.mkdir      = vfatx_mkdir,
	.mknod      = vfatx_mknod,
	.open       = vfatx_open,
	.read       = vfatx_read,
	.readdir    = vfatx_readdir,
	.readlink   = vfatx_readlink,
	.release    = vfatx_close,
	.rename     = vfatx_rename,
	.rmdir      = vfatx_rmdir,
	.statfs     = vfatx_statfs,
	.symlink    = vfatx_symlink,
	.truncate   = vfatx_truncate,
	.unlink     = vfatx_unlink,
	.utimens    = vfatx_utimens,
	.write      = vfatx_write,
};

int main(int argc, char **argv)
{
	char **aptr, **new_argv;
	int new_argc = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s [/source_dir] /target_dir [fuseopts]\n", *argv);
		return EXIT_FAILURE;
	}
	root_dir = argv[1];
	umask(0);
	if ((root_fd = open(root_dir, O_DIRECTORY)) < 0) {
		fprintf(stderr, "Could not open(\"%s\"): %s\n",
		        root_dir, strerror(errno));
		abort();
	}

	new_argv = malloc(sizeof(char *) * (argc + 4));
	new_argv[new_argc++] = argv[0];
	new_argv[new_argc++] = "-f";
	new_argv[new_argc++] = "-ofsname=vfat-x";

	if (argc >= 3 && *argv[2] != '-') {
		aptr = &argv[2];
	} else if (argc >= 2) {
	        aptr = &argv[1];
		new_argv[new_argc++] = "-ononempty";
	}

	while (*aptr != NULL)
		new_argv[new_argc++] = *aptr++;
	new_argv[new_argc] = NULL;

	return fuse_main(new_argc, new_argv, &vfatx_ops, NULL);
}
