/*
 *	posixovl - POSIX overlay filesystem
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
#define S_IFHARDLNK       (S_IFLNK | S_ISVTX)
#define S_IFSOFTLNK       (S_IFLNK | S_IRWXUGO)
#define S_ISHARDLNK(mode) ((mode) == S_IFHARDLNK)
#define S_ISSOFTLNK(mode) ((mode) == S_IFSOFTLNK)

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

/* Buggers */
#define should_not_happen() \
	do { \
		fprintf(stderr, "Should never happen! %s:%u\n", \
		        __FILE__, __LINE__); \
		abort(); \
	} while (0)
#define hcb_got_busted(path) \
	fprintf(stderr, "HCB %s got busted\n", (path))

/* Shortcut */
#define XRET(v) \
	return ({ \
		int __ret = (v); \
		(__ret >= 0) ? __ret : -errno; \
	})

/* Definitions */
#define HCB_PREFIX     ".pxovl."
#define HCB_PREFIX_LEN (sizeof(HCB_PREFIX) - 1)
#define HL_DNODE_PREFIX     ".pxovd."
#define HL_DNODE_PREFIX_LEN (sizeof(HL_DNODE_PREFIX) - 1)
#define HL_INODE_PREFIX     ".pxovn."
#define HL_INODE_PREFIX_LEN (sizeof(HL_INODE_PREFIX) - 1)

struct hcb {
	char buf[PATH_MAX], tbuf[PATH_MAX];
	const char *target;
	mode_t mode;
	nlink_t nlink;
	uid_t uid;
	gid_t gid;
	dev_t rdev;
	size_t size;
};

/* Global */
static const char *root_dir;
static int root_fd;
static unsigned int perform_setfsxid;
static pthread_mutex_t posixovl_protect = PTHREAD_MUTEX_INITIALIZER;

static inline int lock_read(int fd)
{
	static const struct flock fl = {
		.l_type   = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	return fcntl(fd, F_SETLK, &fl);
}

static inline int lock_write(int fd)
{
	static const struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	return fcntl(fd, F_SETLK, &fl);
}

/*
 * at - turn a virtual path into a relative (to root_fd) one
 */
static __attribute__((pure)) const char *at(const char *in)
{
	if (*in != '/')
		should_not_happen();
	if (in[1] == '\0')
		return ".";
	return in + 1;
}

/*
 * __hl_dtoi - build the HL.I-node path from the HL.D-node path
 */
static void __hl_dtoi(char *dest, size_t destsize, const char *src)
{
	char *last, *p;

	strncpy(dest, src, destsize);
	dest[destsize-1] = '\0';

	last = dest;
	while ((p = strstr(last, "/" HL_DNODE_PREFIX)) != NULL)
		last = p + 1;

	memcpy(last, HL_INODE_PREFIX, HL_INODE_PREFIX_LEN);
	return;
}

#define hl_dtoi(dest, src) __hl_dtoi((dest), sizeof(dest), (src))

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
	 * For directories, the HCB must be stored within the directory,
	 * not "alongside" it. This is because there is no possible parallel
	 * entry (on the same filesystem) for the root directory.
	 */
	ret = fstatat(root_fd, at(src), &sb, AT_SYMLINK_NOFOLLOW);
	if (ret == 0 && S_ISDIR(sb.st_mode)) {
		ret = snprintf(dest, destsize, "%s/" HCB_PREFIX, src);
		if (ret > destsize)
			return -ENAMETOOLONG;
		return 0;
	}

	filename_part = strrchr(src, '/');
	if (filename_part++ == NULL)
		should_not_happen();

	ret = snprintf(dest, destsize, "%.*s" HCB_PREFIX "%s",
	      filename_part - directory_part, directory_part,
	      filename_part);
	if (ret > destsize)
		return -ENAMETOOLONG;
	return 0;
}

#define real_to_hcb(dest, src) __real_to_hcb((dest), sizeof(dest), (src))

/*
 * hcb_read -
 * @path:	path to HCB (used for debug and unlink)
 * @info:	destination structure
 * @fd:		fd to read from
 */
static int hcb_read(const char *path, struct hcb *info, int fd)
{
	const char *s_mode, *s_nlink, *s_uid, *s_gid, *s_rdev;
	char *toul_ptr = NULL;
	ssize_t ret;

	if ((ret = read(fd, info->buf, sizeof(info->buf) - 1)) < 0)
		return -errno;
	info->buf[ret] = '\0';
	if (ret == 0)
		return -ENOENT;
	info->size = ret;

	s_mode  = info->buf;
	s_nlink = strchr(info->buf, ' ');
	if (s_nlink++ == NULL)
		goto busted;

	s_uid = strchr(s_nlink, ' ');
	if (s_uid++ == NULL)
		goto busted;

	s_gid = strchr(s_uid, ' ');
	if (s_gid++ == NULL)
		goto busted;

	s_rdev = strchr(s_gid, ' ');
	if (s_rdev++ == NULL)
		goto busted;

	info->target = strchr(s_rdev, ' ');
	if (info->target++ == NULL)
		goto busted;

	info->mode  = strtoul(s_mode, NULL, 8);
	info->nlink = strtoul(s_nlink, NULL, 0);
	info->uid   = strtoul(s_uid, NULL, 0);
	info->gid   = strtoul(s_gid, NULL, 0);
	info->rdev  = strtoul(s_rdev, &toul_ptr, 0);
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
	ret = snprintf(info->buf, sizeof(info->buf), "%o %u %lu %lu %lu:%lu %s",
	      static_cast(unsigned int, info->mode),
	      static_cast(unsigned int, info->nlink),
	      static_cast(unsigned long, info->uid),
	      static_cast(unsigned long, info->gid),
	      COMPAT_MAJOR(info->rdev), COMPAT_MINOR(info->rdev), info->tbuf);
	if (ret >= sizeof(info->buf))
		return -EIO;

	z   = strlen(info->buf);
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

/*
 * hcb_lookup - read a HCB
 * @path:	pathname to the HCB (e.g. /foo/bar/.pxovl.filename or
 *		/foo/bar/.pxovn.ID)
 * @info:	destination buffer
 * @follow:	follow S_IFHARDLNK objects
 */
static int hcb_lookup(const char *path, struct hcb *info, unsigned int follow)
{
	char hinode_path[PATH_MAX];
	int fd, ret;

	fd = openat(root_fd, at(path), O_RDONLY);
	if (fd < 0)
		return -errno;
	if (lock_read(fd) < 0)
		return -errno;
	ret = hcb_read(path, info, fd);
	close(fd);
	if (ret < 0)
		return ret;
	if (follow && S_ISHARDLNK(info->mode)) {
		/*
		 * Only do one dereference - for safety. (Normally, no
		 * S_IFHARDLNK points to another S_IFHARDLNK, but always
		 * directly to the master D-node.)
		 */
		hl_dtoi(hinode_path, info->target);
		return hcb_lookup(hinode_path, info, 0);
	}
	return 0;
}

/*
 * hcb_lookup_4readdir -
 * @dir:	working directory
 * @name:	file
 * @info:	
 *
 * Combines the working directory @dir with @name (to form an absolute path),
 * transforms it into the HCB filename, then calls hcb_lookup().
 */
static inline int hcb_lookup_4readdir(const char *dir, const char *name,
    struct hcb *info)
{
	char path[PATH_MAX], hcb_path[PATH_MAX];
	int ret;

	ret = snprintf(path, sizeof(path), "%s%s", dir, name);
	if (ret >= sizeof(path))
		return -ENAMETOOLONG;
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	return hcb_lookup(hcb_path, info, 1);
}

/*
 * hcb_init - Create or update HCB
 * @hcb_path:	path to the HCB
 * @mode:	file mode and permissions (or -1 for no change)
 * @nlink:	nlink count (or -1 for no change)
 * @uid:	owning user (or -1 for no change)
 * @gid:	owning group (or -1 for no change)
 * @rdev:	device number for block and character devices
 *		(or -1 for no change)
 * @target:	target for soft and hardlinks (or %NULL for no change)
 * @flags:	flags for openat(). May be 0 or %O_EXCL.
 */
static int hcb_init(const char *hcb_path, mode_t mode, nlink_t nlink,
    uid_t uid, gid_t gid, dev_t rdev, const char *target, unsigned int flags)
{
	struct hcb info;
	int fd, ret;

	if (flags != 0 && flags != O_EXCL)
		should_not_happen();

	fd = openat(root_fd, at(hcb_path), O_RDWR | O_CREAT | flags,
	     S_IRUGO | S_IWUSR);
	if (fd < 0)
		return -errno;
	if (lock_write(fd) < 0)
		return -errno;
	ret = hcb_read(hcb_path, &info, fd);
	if (ret == -ENOENT) {
		const struct fuse_context *ctx = fuse_get_context();
		info.mode   = mode;
		info.nlink  = 1;
		info.uid    = ctx->uid;
		info.gid    = ctx->gid;
		info.rdev   = 0;
		info.size   = 0;
		info.target = NULL;
	} else if (ret < 0) {
		goto err;
	}

	/* update */
	if (mode != -1)
		info.mode = mode;
	if (nlink != -1)
		info.nlink = nlink;
	if (uid != -1)
		info.uid = uid;
	if (gid != -1)
		info.gid = gid;
	if (rdev != -1)
		info.rdev = rdev;

	if (target != NULL)
		strncpy(info.tbuf, target, sizeof(info.tbuf));
	else if (info.target != NULL)
		/* move symlink target out of the way (from buf into tbuf) */
		strncpy(info.tbuf, info.target, sizeof(info.tbuf));
	else
		*info.tbuf = '\0';
	info.tbuf[sizeof(info.tbuf)-1] = '\0';

	/* write out */
	ret = hcb_write(hcb_path, &info, fd);
 err:
	close(fd);
	return ret;
}

/*
 * hcb_init_follow - follow HCB to hardlink master and apply changes
 * @hcb_path:	path to HCB
 * @mode:	new permissions (or -1 for no change)
 * @uid:	new owning user (or -1 for no change)
 * @gid:	new owning group (or -1 for no change)
 *
 * hcb_init_follow() follows the HCB pointer in a S_IFHARDLNK and then applies
 * changes. @mode is enforced to NOT contain a file mode, only the
 * _permissions_ (and this is checked). Only callers hence are chown() and
 * chmod().
 */
static int hcb_init_follow(const char *hcb_path, mode_t mode, uid_t uid,
    gid_t gid)
{
	char hinode_path[PATH_MAX];
	struct hcb info;
	int fd, ret;

	fd = openat(root_fd, at(hcb_path), O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT)
			return hcb_init(hcb_path, mode, -1, uid, gid,
			       -1, NULL, 0);
		else
			return -errno;
	}
	if (lock_read(fd) < 0)
		return -errno;
	ret = hcb_read(hcb_path, &info, fd);
	close(fd);
	if (ret < 0)
		return ret;
	if (S_ISHARDLNK(info.mode)) {
		hl_dtoi(hinode_path, info.target);
		return hcb_init(hinode_path, mode, -1, uid, gid, -1, NULL, 0);
	}
	return hcb_init(hcb_path, mode, -1, uid, gid, -1, NULL, 0);
}

static __attribute__((pure)) inline unsigned int is_hcb_name(const char *name)
{
	return strncmp(name, HCB_PREFIX, HCB_PREFIX_LEN) == 0 ||
	       strncmp(name, HL_DNODE_PREFIX, HL_DNODE_PREFIX_LEN) == 0 ||
	       strncmp(name, HL_INODE_PREFIX, HL_INODE_PREFIX_LEN) == 0;
}

static __attribute__((pure)) inline unsigned int is_hcb(const char *path)
{
	const char *file = strrchr(path, '/');
	if (file++ == NULL)
		should_not_happen();
	return is_hcb_name(file);
}

static int generic_permission(const struct hcb *info, unsigned int mask)
{
	const struct fuse_context *ctx = fuse_get_context();
	mode_t mode = info->mode;

	if (ctx->uid == info->uid)
		mode >>= 6;
	else if (ctx->gid == info->gid)
		/*
		 * More precisely, we would have to check if info->gid is in
		 * all the supplementary groups of the process ctx->pid. But
		 * there seems to be no way to getgroups() a different process.
		 */
		mode >>= 3;

	return ((mode & mask & (R_OK | W_OK | X_OK)) == mask) ? 0 : -EACCES;
}

static inline void setfsxid(void)
{
	const struct fuse_context *ctx;
	if (!perform_setfsxid)
		return;
	ctx = fuse_get_context();
	if (setfsuid(ctx->uid) < 0)
		perror("setfsuid");
	if (setfsgid(ctx->gid) < 0)
		perror("setfsgid");
	return;
}

static inline void setrexid(void)
{
	const struct fuse_context *ctx;
	if (!perform_setfsxid)
		return;
	ctx = fuse_get_context();
	if (setreuid(ctx->uid, -1) < 0)
		perror("setreuid()");
	if (setregid(ctx->gid, -1) < 0)
		perror("setregid()");
	return;
}

static int posixovl_access(const char *path, int mode)
{
	char hcb_path[PATH_MAX];
	struct hcb info;
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	setrexid();
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;

	ret = hcb_lookup(hcb_path, &info, 1);
	if (ret == -ENOENT) {
		/* No HCB, try real file */
		XRET(faccessat(root_fd, at(path), mode, AT_SYMLINK_NOFOLLOW));
	} else if (ret < 0) {
		return ret;
	}

	return generic_permission(&info, mode);
}

static int posixovl_chmod(const char *path, mode_t mode)
{
	char hcb_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	setfsxid();
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	return hcb_init_follow(hcb_path, mode, -1, -1);
}

static int posixovl_chown(const char *path, uid_t uid, gid_t gid)
{
	char hcb_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	setfsxid();
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	return hcb_init_follow(hcb_path, -1, uid, gid);
}

static int posixovl_close(const char *path, struct fuse_file_info *filp)
{
	XRET(close(filp->fh));
}

static __attribute__((pure)) inline
unsigned int could_be_too_long(const char *path)
{
	/* Longest possible case is S_ISDIR: /root/path/.pxovl. */
	return strlen(root_dir) + strlen(path) +
	       1 + HCB_PREFIX_LEN >= PATH_MAX;
}

static int posixovl_create(const char *path, mode_t mode,
    struct fuse_file_info *filp)
{
	int fd;

	if (is_hcb(path))
		return -EPERM;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	setfsxid();
	fd = openat(root_fd, at(path), filp->flags, mode);
	if (fd < 0)
		return -errno;

	filp->fh = fd;
	return 0;
}

static int posixovl_ftruncate(const char *path, off_t length,
    struct fuse_file_info *filp)
{
	setfsxid();
	XRET(ftruncate(filp->fh, length));
}

static int hl_demote(const char *hdnode_path, const char *path,
    const char *hcb_path)
{
	char hinode_path[PATH_MAX];
	int ret;

	hl_dtoi(hinode_path, hdnode_path);
	pthread_mutex_lock(&posixovl_protect);
	if (unlinkat(root_fd, at(path), 0) < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return -errno;
	}
	unlinkat(root_fd, at(hcb_path), 0);
	if (renameat(root_fd, at(hdnode_path), root_fd, at(path)) < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		ret = -errno;
		fprintf(stderr, "Inconsistency (1) during hardlink demotion!\n");
		return ret;
	}
	if (renameat(root_fd, at(hinode_path), root_fd, at(hcb_path)) < 0)
		fprintf(stderr, "Inconsistency (2) during hardlink demotion!\n");
	pthread_mutex_unlock(&posixovl_protect);
	return 0;
}

static int posixovl_getattr(const char *path, struct stat *sb)
{
	struct hcb info_first, info_last;
	char hcb_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;

	setfsxid();
	ret = fstatat(root_fd, at(path), sb, AT_SYMLINK_NOFOLLOW);
	if (ret < 0)
		return -errno;

	if (!S_ISDIR(sb->st_mode) && !S_ISLNK(sb->st_mode))
		/*
		 * Files by default start without an +x bit.
		 * Symlinks (if supported by the underlying fs)
		 * are left as-is.
		 */
		sb->st_mode &= ~S_IXUGO;

	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;

	/*
	 * Need to check for hardlink and grab the HL.D-node inode number
	 */
	ret = hcb_lookup(hcb_path, &info_first, 0);
	if (ret == -ENOENT || ret == -EACCES)
		return 0;
	else if (ret < 0)
		return ret;

	if (S_ISHARDLNK(info_first.mode)) {
		struct stat sb2;

		ret = fstatat(root_fd, at(info_first.target),
		      &sb2, AT_SYMLINK_NOFOLLOW);
		if (ret < 0 && errno == ENOENT) {
			/* Hardlink pointer is bogus */
			sb->st_mode  = 0;
			sb->st_nlink = 0;
			return -EIO;
		}
		sb->st_ino  = sb2.st_ino;
		sb->st_size = sb2.st_size;
	}

	/*
	 * Read HCB (or HL.I-node HCB) attributes
	 */
	ret = hcb_lookup(hcb_path, &info_last, 1);
	if (ret == -ENOENT || ret == -EACCES) {
		/*
		 * Either the HCB suddenly disappeared or the hardlink is
		 * broken. Make `ls -l` print a lot of ???s.
		 */
		sb->st_mode  = 0;
		sb->st_nlink = 0;
		return 0;
	} else if (ret < 0) {
		return ret;
	}

	/* HCB also exists, update attributes. */
	sb->st_mode  = info_last.mode;
	sb->st_nlink = info_last.nlink;
	sb->st_uid   = info_last.uid;
	sb->st_gid   = info_last.gid;
	sb->st_rdev  = info_last.rdev;
	if (!S_ISREG(info_last.mode) && !S_ISDIR(info_last.mode))
		sb->st_size = info_last.size;
	if (S_ISHARDLNK(info_first.mode) && info_last.nlink == 1)
		hl_demote(info_first.target, path, hcb_path);
	return 0;
}

static int posixovl_fgetattr(const char *path, struct stat *sb,
    struct fuse_file_info *filp)
{
	/*
	 * Need to use the normal getattr because we need to check for the
	 * HCB too, not just @filp->fh.
	 */
	return posixovl_getattr(path, sb);
}

static void *posixovl_init(struct fuse_conn_info *conn)
{
	/*
	 * There is no fopendirat(), we need to use fchdir() and
	 * opendir(relative_path) instead.
	 */
	if (fchdir(root_fd) < 0)
		abort();
	return NULL;
}

/*
 * hl_promote - transform file into hardlink master
 * @path:	path to real file
 * @hcb_path:	path to HCB
 * @info:	HCB data (or %NULL)
 */
static int hl_promote(const char *path, const char *hcb_path,
    const struct hcb *info)
{
	char hdnode_path[PATH_MAX], hinode_path[PATH_MAX];
	struct stat orig_sb, work_sb;
	int fd, ret;

	/*
	 * Create a unique ID. Note that there may be underlying filesystems
	 * where inode numbers are dynamically generated. Hence they may
	 * overlap with posixovl IDs (encoded into the filename) from a
	 * previous mount, hence we rand() should the ID already exist.
	 */
	if (fstatat(root_fd, at(path), &orig_sb, AT_SYMLINK_NOFOLLOW) < 0)
		return -errno;

	work_sb.st_ino = orig_sb.st_ino;
	while (1) {
		snprintf(hdnode_path, sizeof(hdnode_path),
		         "/" HL_DNODE_PREFIX "%lu",
			 static_cast(unsigned long, work_sb.st_ino));
		snprintf(hinode_path, sizeof(hinode_path),
		         "/" HL_INODE_PREFIX "%lu",
			 static_cast(unsigned long, work_sb.st_ino));
		if (fstatat(root_fd, at(hdnode_path), &work_sb,
		    AT_SYMLINK_NOFOLLOW) == 0) {
			work_sb.st_ino = rand();
			continue;
		}
		if (errno == ENOENT)
			/* ok, can use this ID */
			break;
		return -errno;
	}

	/* Move real file to HL.D-node */
	ret = renameat(root_fd, at(path), root_fd, at(hdnode_path));
	if (ret < 0)
		return -errno;

	/* move HCB to HL.I-node */
	if (info != NULL) {
		ret = renameat(root_fd, at(hcb_path), root_fd, at(hinode_path));
		if (ret < 0) {
			ret = -errno;
			goto out;
		}
		ret = hcb_init(hinode_path, -1, 1, -1, -1, -1, NULL, 0);
	} else {
		mode_t mode = orig_sb.st_mode;

		if (!S_ISDIR(orig_sb.st_mode) && !S_ISLNK(orig_sb.st_mode))
			mode &= ~S_IXUGO;
		/* initialize nlink counter */
		ret = hcb_init(hinode_path, mode, 1, -1, -1, -1, NULL, O_EXCL);
	}

	if (ret < 0)
		goto out2;

	/* initialize first link */
	ret = hcb_init(hcb_path, S_IFHARDLNK, -1, -1, -1, -1,
	      hdnode_path, O_EXCL);
	if (ret < 0)
		goto out3;

	/* instantiate first link into readdir visibility */
	fd = openat(root_fd, at(path), O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		goto out4;
	}

	return 0;

 out4:
	unlinkat(root_fd, at(hcb_path), 0);
 out3:
	unlinkat(root_fd, at(hinode_path), 0);
 out2:
	if (info != NULL)
		renameat(root_fd, at(hinode_path), root_fd, at(hcb_path));
 out:
	renameat(root_fd, at(hdnode_path), root_fd, at(path));
	return ret;
}

/*
 * hl_up_nlink - increase nlink count of hardlink master
 * @hdnode_path:	name of the HL.D-node
 */
static int hl_up_nlink(const char *hdnode_path)
{
	char hinode_path[PATH_MAX];
	struct hcb info;
	int ret;

	hl_dtoi(hinode_path, hdnode_path);
	ret = hcb_lookup(hinode_path, &info, 0);
	if (ret < 0)
		return ret;
	return hcb_init(hinode_path, -1, info.nlink + 1, -1, -1, -1, NULL, 0);
}

/*
 * hl_drop - drop nlink count of hardlink master
 * @hdnode_path:	name of the HL.D-node
 *
 * Drop the nlink of the hardlink master by one, and if it reaches zero,
 * unlink the D-node.
 */
static int hl_drop(const char *hdnode_path)
{
	char hinode_path[PATH_MAX];
	struct hcb info;
	int ret;

	hl_dtoi(hinode_path, hdnode_path);
	pthread_mutex_lock(&posixovl_protect);
	ret = hcb_lookup(hinode_path, &info, 0);
	if (ret < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}

	if (info.nlink == 1) {
		unlinkat(root_fd, at(hdnode_path), 0);
		unlinkat(root_fd, at(hinode_path), 0);
		pthread_mutex_unlock(&posixovl_protect);
		return 0;
	}

	ret = hcb_init(hinode_path, -1, info.nlink - 1, -1, -1, -1, NULL, 0);
	pthread_mutex_unlock(&posixovl_protect);
	return ret;
}

/*
 * hl_instantiate -
 * @oldpath:
 * @newpath:
 *
 * This is perhaps the most expensive operation among all.
 * posixovl_protect must be held.
 */
static int hl_instantiate(const char *oldpath, const char *newpath)
{
	char hcb_oldpath[PATH_MAX], hcb_newpath[PATH_MAX];
	struct hcb info;
	int fd, ret;

	if ((ret = real_to_hcb(hcb_oldpath, oldpath)) < 0)
		return ret;
	if ((ret = real_to_hcb(hcb_newpath, newpath)) < 0)
		return ret;

	ret = hcb_lookup(hcb_oldpath, &info, 0);
	if (ret == -ENOENT) {
		/* If no HCB attached... */
		if ((ret = hl_promote(oldpath, hcb_oldpath, NULL)) < 0)
			return ret;
		/* Relookup to get the master name */
		if ((ret = hcb_lookup(hcb_oldpath, &info, 0)) < 0)
			return ret;
	} else if (ret == 0 && !S_ISHARDLNK(info.mode)) {
		/*
		 * ...or if not already a hardlink slave,
		 * transform the first link into a hardlink master.
		 */
		if ((ret = hl_promote(oldpath, hcb_oldpath, &info)) < 0)
			return ret;
		/* Relookup to get the master name */
		if ((ret = hcb_lookup(hcb_oldpath, &info, 0)) < 0)
			return ret;
	} else if (ret < 0) {
		return -errno;
	}

	/* now we can do the Nth link */
	if ((ret = hl_up_nlink(info.target)) < 0)
		return ret;

	ret = hcb_init(hcb_newpath, S_IFHARDLNK, -1, -1, -1, -1,
	      info.target, O_EXCL);
	if (ret < 0)
		goto out;

	fd = openat(root_fd, at(newpath), O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		goto out2;
		return ret;
	}

	close(fd);
	return 0;

 out2:
	unlinkat(root_fd, at(hcb_newpath), 0);
 out:
	hl_drop(info.target);
	return ret;
}

static int posixovl_link(const char *oldpath, const char *newpath)
{
	const struct fuse_context *ctx;
	struct stat sb;
	int ret;

	if (is_hcb(oldpath))
		return -ENOENT;
	if (is_hcb(newpath))
		return -EPERM;
	if (could_be_too_long(oldpath) || could_be_too_long(newpath))
		return -ENAMETOOLONG;

	/*
	 * Kernel/FUSE already takes care of prohibiting hardlinking
	 * directories. We never get to see these.
	 */
	setfsxid();
	ret = linkat(root_fd, at(oldpath), root_fd, at(newpath), 0);
	if (ret < 0 && errno != EPERM)
		return ret;
	else if (ret >= 0)
		return 0;

	/* Extra check for ownerless filesystems */
	if ((ret = posixovl_getattr(oldpath, &sb)) < 0)
		return ret;
	ctx = fuse_get_context();
	if (sb.st_uid != ctx->uid && posixovl_access(oldpath, R_OK | W_OK) < 0)
		return -EPERM;

	pthread_mutex_lock(&posixovl_protect);
	ret = hl_instantiate(oldpath, newpath);
	pthread_mutex_unlock(&posixovl_protect);
	return ret;
}

static int posixovl_lock(const char *path, struct fuse_file_info *filp,
    int cmd, struct flock *fl)
{
	setfsxid();
	XRET(fcntl(filp->fh, cmd, fl));
}

static int posixovl_mkdir(const char *path, mode_t mode)
{
	if (is_hcb(path))
		return -EPERM;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	setfsxid();
	XRET(mkdirat(root_fd, at(path), mode));
}

static int posixovl_mknod(const char *path, mode_t mode, dev_t rdev)
{
	char hcb_path[PATH_MAX];
	int fd, ret;

	if (is_hcb(path))
		return -EPERM;

	setfsxid();
	ret = mknodat(root_fd, at(path), mode, rdev);
	if (ret < 0 && errno != EPERM)
		return ret;
	else if (ret >= 0)
		return 0;

	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	/*
	 * The HCB is created first - since that one does not show up in
	 * readdir() and is not accessible either.
	 * Same goes for posixovl_symlink().
	 */
	pthread_mutex_lock(&posixovl_protect);
	ret = hcb_init(hcb_path, mode, -1, -1, -1, rdev, NULL, O_EXCL);
	if (ret < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}

	fd = openat(root_fd, at(path), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		unlinkat(root_fd, at(path), 0);
	}
	pthread_mutex_unlock(&posixovl_protect);
	close(fd);
	return ret;
}

static int posixovl_open(const char *path, struct fuse_file_info *filp)
{
	int fd;

	if (is_hcb(path))
		return -ENOENT;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	setfsxid();
	/*
	 * no need to handle non-regular files -- kernel (S_ISBLK, S_IFCHR,
	 * S_IFIFO, S_IFSOCK) and FUSE (S_IFLNK) do that for us.
	 */
	if ((fd = openat(root_fd, at(path), filp->flags)) < 0)
		return -errno;

	filp->fh = fd;
	return 0;
}

static int posixovl_read(const char *path, char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	lseek(filp->fh, offset, SEEK_SET);
	XRET(read(filp->fh, buffer, size));
}

static int posixovl_readdir(const char *path, void *buffer,
    fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *filp)
{
	const struct dirent *dentry;
	struct hcb info;
	struct stat sb;
	int ret = 0;
	DIR *ptr;

	if (is_hcb(path))
		return -ENOENT;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;
	setfsxid();
	/*
	 * Current working directory is root_fd (per posixovl_init()).
	 * Let's hope opendir(relative_path) works.
	 */
	if ((ptr = opendir(at(path))) == NULL)
		return -errno;

	memset(&sb, 0, sizeof(sb));
	while ((dentry = readdir(ptr)) != NULL) {
		if (is_hcb_name(dentry->d_name))
			continue;

		sb.st_ino  = dentry->d_ino;
		sb.st_mode = (unsigned long)dentry->d_type << 12;

		/* As usual, non-directories start without +x */
		if (!S_ISDIR(sb.st_mode) && !S_ISLNK(sb.st_mode))
			sb.st_mode &= ~S_IXUGO;

		ret = hcb_lookup_4readdir(path, dentry->d_name, &info);
		if (ret < 0 && ret != -ENOENT && ret != -EACCES)
			break;
		else if (ret == 0)
			sb.st_mode = info.mode;

		ret = 0;
		if ((*filldir)(buffer, dentry->d_name, &sb, 0) > 0)
			break;
	}

	closedir(ptr);
	return ret;
}

static int posixovl_readlink(const char *path, char *dest, size_t size)
{
	struct hcb info;
	char hcb_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;

	setfsxid();
	ret = readlinkat(root_fd, at(path), dest, size);
	if (ret < 0 && errno != EINVAL)
		return ret;
	else if (ret >= 0)
		return 0;

	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	ret = hcb_lookup(hcb_path, &info, 1);
	if (ret < 0)
		return ret;
	if (!S_ISLNK(info.mode))
		return -EINVAL; /* not a symbolic link */

	memset(dest, 0, size);
	strncpy(dest, info.target, size - 1);
	return 0;
}

static int posixovl_rename(const char *oldpath, const char *newpath)
{
	char hcb_oldpath[PATH_MAX], hcb_newpath[PATH_MAX];
	struct hcb info;
	struct stat sb;
	int ret, ret_2;

	if (is_hcb(oldpath))
		return -ENOENT;
	if (is_hcb(newpath))
		return -EPERM;
	if (could_be_too_long(oldpath) || could_be_too_long(newpath))
		return -ENAMETOOLONG;

	/* We do not check for a real file until fstatat(). */
	if ((ret = real_to_hcb(hcb_oldpath, oldpath)) < 0)
		return ret;
	setfsxid();
	ret = hcb_lookup(hcb_oldpath, &info, 0);
	if (ret == -ENOENT)
		/*
		 * No HCB. Existence of real oldfile unknown,
		 * but does not matter here.
		 */
		XRET(renameat(root_fd, at(oldpath), root_fd, at(newpath)));
	if (ret < 0)
		return ret;

	/* HCB exists. */
	if ((ret = real_to_hcb(hcb_newpath, newpath)) < 0)
		return ret;
	ret = fstatat(root_fd, at(oldpath), &sb, AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		if (errno == ENOENT)
			/*
			 * Old HCB exists, real oldfile not, also simple.
			 */
			XRET(renameat(root_fd, at(hcb_oldpath),
			              root_fd, at(hcb_newpath)));
		else
			return -errno;
	}

	/* Real oldfile _and_ an old HCB. Needs special locking. */
	pthread_mutex_lock(&posixovl_protect);
	ret_2 = renameat(root_fd, at(oldpath), root_fd, at(newpath));
	if (ret_2 < 0) {
		ret = -errno;
		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}
	ret_2 = renameat(root_fd, at(hcb_oldpath), root_fd, at(hcb_newpath));
	if (ret_2 < 0) {
		/* !@#$%^& - error. Need to rename old file back. */
		ret = -errno;
		if (renameat(root_fd, at(newpath), root_fd, at(oldpath)) < 0)
			/* Even that failed. Keep new name, but kill HCB. */
			unlinkat(root_fd, at(hcb_oldpath), 0);

		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}

	pthread_mutex_unlock(&posixovl_protect);
	return 0;
}

static int posixovl_rmdir(const char *path)
{
	char hcb_path[PATH_MAX];
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	setfsxid();
	if (unlinkat(root_fd, hcb_path, 0) < 0 && errno != ENOENT)
		return -errno;
	XRET(unlinkat(root_fd, at(path), AT_REMOVEDIR));
}

static int posixovl_statfs(const char *path, struct statvfs *sb)
{
	setfsxid();
	if (fstatvfs(root_fd, sb) < 0)
		return -errno;
	sb->f_fsid = 0;
	return 0;
}

static int posixovl_symlink(const char *oldpath, const char *newpath)
{
	char hcb_newpath[PATH_MAX];
	int fd, ret;

	if (is_hcb(newpath))
		return -EPERM;

	setfsxid();
	ret = symlinkat(oldpath, root_fd, at(newpath));
	if (ret < 0 && errno != EPERM)
		return -errno;
	else if (ret >= 0)
		return 0;

	/* symlink() not supported on underlying filesystem */
	if ((ret = real_to_hcb(hcb_newpath, newpath)) < 0)
		return ret;
	if ((ret = real_to_hcb(hcb_newpath, newpath)) < 0)
		return ret;
	pthread_mutex_lock(&posixovl_protect);
	ret = hcb_init(hcb_newpath, S_IFSOFTLNK, -1, -1, -1, -1,
	      oldpath, O_EXCL);
	if (ret < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}

	fd = openat(root_fd, at(newpath), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		unlinkat(root_fd, at(newpath), 0);
	}
	pthread_mutex_unlock(&posixovl_protect);
	close(fd);
	return ret;
}

static int posixovl_truncate(const char *path, off_t length)
{
	char hcb_path[PATH_MAX];
	struct hcb info;
	int fd, ret;

	if (is_hcb(path))
		return -ENOENT;

	setfsxid();
	/*
	 * There is no ftruncateat(), so need to use openat()+ftruncate() here.
	 */
	fd = openat(root_fd, at(path), O_WRONLY);
	if (fd < 0)
		return -errno;
	
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;
	ret = hcb_lookup(hcb_path, &info, 1);
	if (ret < 0 && ret != -ENOENT)
		return ret;
	else if (ret == 0 && !S_ISREG(info.mode) && !S_ISDIR(info.mode))
		/*
		 * A HCB was found. But truncating special
		 * files (e.g. /dev/zero) is invalid.
		 */
		return -EINVAL;

	/* Will return -EISDIR for us if it is a directory. */
	ret = ftruncate(fd, length);
	if (ret < 0)
		ret = -errno;

	close(fd);
	return ret;
}

static int posixovl_unlink(const char *path)
{
	char hcb_path[PATH_MAX];
	struct hcb info;
	int ret;

	if (is_hcb(path))
		return -ENOENT;
	if ((ret = real_to_hcb(hcb_path, path)) < 0)
		return ret;

	/*
	 * Need to unlink the real file first so that the potential case
	 * "HCB non-existant but real file existant" does not happen in
	 * readdir().
	 */
	setfsxid();
	ret = unlinkat(root_fd, at(path), 0);
	if (ret < 0)
		return -errno;

	ret = hcb_lookup(hcb_path, &info, 0);
	if (ret == -ENOENT)
		return 0;
	else if (ret < 0)
		return ret;

	unlinkat(root_fd, at(hcb_path), 0);
	if (S_ISHARDLNK(info.mode))
		hl_drop(info.target);

	/* Can't help but to ignore unlink errors here */
	return 0;
}

static int posixovl_utimens(const char *path, const struct timespec *ts)
{
	struct timeval tv;
	int ret;

	if (is_hcb(path))
		return -ENOENT;

	tv.tv_sec  = ts->tv_sec;
	tv.tv_usec = ts->tv_nsec / 1000;

	setfsxid();
	/*
	 * The time attributes are always applied to the plain file,
	 * never the special file.
	 * (Until a filesystem that cannot store times comes along.)
	 */
	ret = futimesat(root_fd, at(path), &tv);
	XRET(ret);
}

static int posixovl_write(const char *path, const char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	lseek(filp->fh, offset, SEEK_SET);
	XRET(write(filp->fh, buffer, size));
}

static unsigned int user_allow_other(void)
{
	unsigned int ret = 0;
	char buf[64];
	FILE *fp;

	if ((fp = fopen("/etc/fuse.conf", "r")) == NULL)
		return 0;
	while (fgets(buf, sizeof(buf), fp) != NULL)
		/* no fancy line ending checks or anything */
		if (strncmp(buf, "user_allow_other",
		    sizeof("user_allow_other") - 1) == 0) {
			ret = 1;
			break;
		}

	fclose(fp);
	return ret;
}

static const struct fuse_operations posixovl_ops = {
	.access     = posixovl_access,
	.chmod      = posixovl_chmod,
	.chown      = posixovl_chown,
	.create     = posixovl_create,
	.fgetattr   = posixovl_fgetattr,
	.ftruncate  = posixovl_ftruncate,
	.getattr    = posixovl_getattr,
	.init       = posixovl_init,
	.link       = posixovl_link,
	.lock       = posixovl_lock,
	.mkdir      = posixovl_mkdir,
	.mknod      = posixovl_mknod,
	.open       = posixovl_open,
	.read       = posixovl_read,
	.readdir    = posixovl_readdir,
	.readlink   = posixovl_readlink,
	.release    = posixovl_close,
	.rename     = posixovl_rename,
	.rmdir      = posixovl_rmdir,
	.statfs     = posixovl_statfs,
	.symlink    = posixovl_symlink,
	.truncate   = posixovl_truncate,
	.unlink     = posixovl_unlink,
	.utimens    = posixovl_utimens,
	.write      = posixovl_write,
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
	new_argv[new_argc++] = "-ouse_ino,fsname=posix-overlay";

	if (argc >= 3 && *argv[2] != '-') {
		aptr = &argv[2];
	} else if (argc >= 2) {
	        aptr = &argv[1];
		new_argv[new_argc++] = "-ononempty";
	}

	perform_setfsxid = geteuid() == 0;
	if (perform_setfsxid || user_allow_other())
		new_argv[new_argc++] = "-oallow_other";

	while (*aptr != NULL)
		new_argv[new_argc++] = *aptr++;
	new_argv[new_argc] = NULL;

	return fuse_main(new_argc, new_argv, &posixovl_ops, NULL);
}
