/*
 *	posixovl - POSIX overlay filesystem
 *	Copyright Jan Engelhardt, 2007-2008,2013
 *
 *	Development of posixovl sponsored by Slax (http://www.slax.org/)
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <attr/xattr.h>
#include "config.h"
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
#ifndef NDEBUG
#	define should_never_happen() \
		do { \
			fprintf(stderr, "CRITICAL: Should NEVER happen! %s:%u\n", \
			        __FILE__, __LINE__); \
			abort(); \
		} while (false)
#	define should_not_happen() \
		do { \
			fprintf(stderr, "WARNING: Should not happen! %s:%u\n", \
			        __FILE__, __LINE__); \
		} while (false)
#else
#	define should_never_happen() do {} while (false)
#	define should_not_happen()   do {} while (false)
#endif
#define hcb_got_busted(path) \
	fprintf(stderr, "HCB %s is corrupt\n", (path))

/* Definitions */

#define HCB_PREFIX     ".pxovl."
#define HCB_PREFIX_LEN (sizeof(HCB_PREFIX) - 1)
/*
 * Trailing dots may be eaten, so we need to check some filenames for
 * another variant.
 */
#define HCB_PREFIX1    ".pxovl"

#define HL_DNODE_PREFIX     ".pxovd."
#define HL_DNODE_PREFIX_LEN (sizeof(HL_DNODE_PREFIX) - 1)
#define HL_INODE_PREFIX     ".pxovn."
#define HL_INODE_PREFIX_LEN (sizeof(HL_INODE_PREFIX) - 1)

enum {
	/* extra errno codes */
	ENOENT_HCB = 4096,
};

/**
 * ll_hcb - lowlevel HCB
 * @buf:	buffer for contents of HCB file
 * @new_target:	buffer to hold the link target
 * @target:	pointer to @new_target (always?)
 * rest:	inode properties
 */
struct ll_hcb {
	char buf[PATH_MAX], new_target[PATH_MAX];
	const char *target;
	mode_t mode;
	nlink_t nlink;
	uid_t uid;
	gid_t gid;
	dev_t rdev;
	size_t size;
};

/**
 * The "hidden control block".
 */
struct hcb {
	char path[PATH_MAX];
	struct ll_hcb ll;
	struct stat sb;
	int fd;
};

/* Global */
static mode_t default_mode = S_IRUGO | S_IWUSR;
static unsigned int assume_vfat, single_threaded, hardlink_with_copy;
static const char *root_dir;
static int root_fd;
static pthread_mutex_t posixovl_protect = PTHREAD_MUTEX_INITIALIZER;

static inline int retcode_int(int code)
{
	return (code >= 0) ? code : -errno;
}

static inline ssize_t retcode_ssize(ssize_t code)
{
	return (code >= 0) ? code : -errno;
}

/**
 * Set a read lock on the entire of a file.
 */
static int lock_read(int fd)
{
	static const struct flock fl = {
		.l_type   = F_RDLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	if (single_threaded)
		return 0;
	return fcntl(fd, F_SETLKW, &fl);
}

/**
 * Set a write lock on the entire of a file.
 */
static int lock_write(int fd)
{
	static const struct flock fl = {
		.l_type   = F_WRLCK,
		.l_whence = SEEK_SET,
		.l_start  = 0,
		.l_len    = 0,
	};
	if (single_threaded)
		return 0;
	return fcntl(fd, F_SETLK, &fl);
}

/**
 * at - turn a virtual path into a relative (to root_fd) one
 */
static __attribute__((pure)) const char *at(const char *in)
{
	if (*in != '/')
		should_never_happen();
	if (in[1] == '\0')
		return ".";
	return in + 1;
}

static char *strlcpy(char *dest, const char *src, size_t n)
{
	strncpy(dest, src, n);
	dest[n-1] = '\0';
	return dest;
}

/**
 * __hl_dtoi - build the HL.I-node path from the HL.D-node path
 */
static void __hl_dtoi(char *dest, size_t destsize, const char *src)
{
	char *last, *p;

	strlcpy(dest, src, destsize);
	last = dest;
	while ((p = strstr(last, "/" HL_DNODE_PREFIX)) != NULL)
		last = p + 1;

	memcpy(last, HL_INODE_PREFIX, HL_INODE_PREFIX_LEN);
}

#define hl_dtoi(dest, src) __hl_dtoi((dest), sizeof(dest), (src))

/**
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
		if (strcmp(src, "/") == 0)
			/* Make sure there is only one slash */
			ret = snprintf(dest, destsize, "/" HCB_PREFIX);
		else
			ret = snprintf(dest, destsize, "%s/" HCB_PREFIX, src);

		if (ret > destsize)
			return -ENAMETOOLONG;
		return 0;
	}

	filename_part = strrchr(src, '/');
	if (filename_part++ == NULL)
		should_never_happen();

	if (strncmp(filename_part, HL_DNODE_PREFIX, HL_DNODE_PREFIX_LEN) == 0)
		ret = snprintf(dest, destsize, "%.*s" HL_INODE_PREFIX "%s",
		      (int)(filename_part - directory_part), directory_part,
		      filename_part + HL_DNODE_PREFIX_LEN);
	else
		ret = snprintf(dest, destsize, "%.*s" HCB_PREFIX "%s",
		      (int)(filename_part - directory_part), directory_part,
		      filename_part);
	if (ret > destsize)
		return -ENAMETOOLONG;
	return 0;
}

#define real_to_hcb(dest, src) __real_to_hcb((dest), sizeof(dest), (src))

/**
 * ll_hcb_read - lowlevel read of HCB
 * @path:	path to HCB (used for debug and unlink)
 * @info:	destination structure
 * @fd:		fd to read from
 */
static int ll_hcb_read(const char *path, struct ll_hcb *info, int fd)
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
	strncpy(info->new_target, info->target, sizeof(info->new_target));
	info->new_target[sizeof(info->new_target)-1] = '\0';

	return 0;

 busted:
	hcb_got_busted(path);
	unlinkat(root_fd, at(path), 0);
	return -EINVAL;
}

/**
 * ll_hcb_write - lowlevel write of HCB
 * @path:	path to HCB (used for debug and unlink)
 * @info:	source structure
 * @fd:		fd to write to
 *
 * Recalculates @info->buf from the structure and writes it out.
 */
static int ll_hcb_write(const char *path, struct ll_hcb *info, int fd)
{
	ssize_t ret;
	size_t z;

	if (lseek(fd, 0, SEEK_SET) < 0)
		return -errno;
	if (ftruncate(fd, 0) < 0)
		should_not_happen();
	ret = snprintf(info->buf, sizeof(info->buf), "%o %u %lu %lu %lu:%lu %s",
	      static_cast(unsigned int, info->mode),
	      static_cast(unsigned int, info->nlink),
	      static_cast(unsigned long, info->uid),
	      static_cast(unsigned long, info->gid),
	      COMPAT_MAJOR(info->rdev), COMPAT_MINOR(info->rdev),
	      info->new_target);
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

/**
 * hcb_new - create new HCB
 * @path:	file path (not HCB path)
 * @cb:		destination structure
 * @reuse:	reuse HCB (may have been filled in previously,
 *		by a failed hcb_get() for example)
 */
static int hcb_new(const char *path, struct hcb *cb, unsigned int reuse)
{
	int ret;

	if (reuse) {
		if (cb->fd >= 0)
			should_not_happen();
	} else {
		memset(cb, 0, sizeof(*cb));
		cb->fd = -1;
		if ((ret = real_to_hcb(cb->path, path)) < 0)
			return ret;
		if (fstatat(root_fd, at(path), &cb->sb,
		    AT_SYMLINK_NOFOLLOW) < 0 && errno != ENOENT)
			return -errno;
		if (!S_ISDIR(cb->sb.st_mode))
			cb->sb.st_mode &= ~S_IXUGO;
	}

	cb->ll.mode  = cb->sb.st_mode;
	cb->ll.nlink = cb->sb.st_nlink;
	cb->ll.uid   = cb->sb.st_uid;
	cb->ll.gid   = cb->sb.st_gid;
	cb->ll.rdev  = cb->sb.st_rdev;
	return 0;
}

/**
 * hcb_get - read HCB
 * @path:	fuse-namespace relative file path (L0)
 * @cb:		destination struct
 *
 * Read @path's HCB into @cb. This function does not follow posixovl hardlinks.
 * When the file given by @path was not found, -ENOENT will be returned, but if
 * the HCB was not found, this funciton returns -ENOENT_HCB instead to indicate
 * so.
 */
static int hcb_get(const char *path, struct hcb *cb)
{
	int ret;

	memset(cb, 0, sizeof(*cb));
	cb->fd = -1;

	/* Get inode number, size and times from the L0 file */
	if (fstatat(root_fd, at(path), &cb->sb, AT_SYMLINK_NOFOLLOW) < 0)
		return -errno;

	cb->sb.st_mode &= S_IFMT;
	cb->sb.st_mode |= default_mode;
	if (S_ISDIR(cb->sb.st_mode))
		cb->sb.st_mode |= S_IXUGO;

	if ((ret = real_to_hcb(cb->path, path)) < 0)
		return ret;
	cb->fd = openat(root_fd, at(cb->path), O_RDWR);
	if (cb->fd < 0 && errno == EACCES)
		/* Retry read-only */
		cb->fd = openat(root_fd, at(cb->path), O_RDONLY);
	if (cb->fd < 0) {
		if (errno == ENOENT)
			return -ENOENT_HCB;
		else
			return -errno;
	}
	if (lock_read(cb->fd) < 0) {
		ret = -errno;
		close(cb->fd);
		return ret;
	}
	ret = ll_hcb_read(cb->path, &cb->ll, cb->fd);
	if (ret < 0) {
		close(cb->fd);
		return ret;
	}

	/* and extra attributes from the L0 HCB */
	cb->sb.st_mode  = cb->ll.mode;
	cb->sb.st_nlink = cb->ll.nlink;
	cb->sb.st_uid   = cb->ll.uid;
	cb->sb.st_gid   = cb->ll.gid;
	cb->sb.st_rdev  = cb->ll.rdev;
	if (!S_ISREG(cb->ll.mode) && !S_ISDIR(cb->ll.mode))
		cb->sb.st_size = cb->ll.size;

	return 0;
}

/**
 * hcb_put - release HCB
 * @cb:	data
 *
 * Close the file descriptor to the HCB. This does _not_ flush any changes.
 * (Also because whether a change was made is not recorded. Explicitly call
 * hcb_update().)
 */
static void hcb_put(const struct hcb *cb)
{
	if (cb->fd < 0)
		should_not_happen();
	close(cb->fd);
}

/**
 * hcb_deref - dereference an S_IFHARDLNK HCB
 * @cb:	data
 *
 * If the HCB is an S_IFHARDLNK, follow it and update attributes.
 * Non-hardlinks are ignored and success is returned.
 */
static int hcb_deref(struct hcb *cb)
{
	struct stat sb;
	int ret;

	if (cb->fd < 0)
		should_never_happen();
	if (!S_ISHARDLNK(cb->ll.mode))
		return 0;

	close(cb->fd);
	if (fstatat(root_fd, at(cb->ll.target), &sb,
	    AT_SYMLINK_NOFOLLOW) < 0)
		return -errno;

	/* Some things are stored on the L1 file... */
	cb->sb.st_ino   = sb.st_ino;
	cb->sb.st_size  = sb.st_size;
	cb->sb.st_atime = sb.st_atime;
	cb->sb.st_ctime = sb.st_ctime;
	cb->sb.st_mtime = sb.st_mtime;

	hl_dtoi(cb->path, cb->ll.target);
	cb->fd = openat(root_fd, at(cb->path), O_RDWR);
	if (cb->fd < 0)
		return -errno;
	if (lock_read(cb->fd) < 0) {
		ret = -errno;
		close(cb->fd);
		return ret;
	}
	ret = ll_hcb_read(cb->path, &cb->ll, cb->fd);
	if (ret < 0) {
		close(cb->fd);
		return ret;
	}

	/* ...and some on the L1 HCB */
	cb->sb.st_mode  = cb->ll.mode;
	cb->sb.st_nlink = cb->ll.nlink;
	cb->sb.st_uid   = cb->ll.uid;
	cb->sb.st_gid   = cb->ll.gid;
	cb->sb.st_rdev  = cb->ll.rdev;
	if (!S_ISREG(cb->ll.mode) && !S_ISDIR(cb->ll.mode))
		cb->sb.st_size = cb->ll.size;

	return 0;
}

/**
 * hcb_get_deref - shortcut for hcb_get()+hcb_deref()
 * @path:	virtual path
 * @cb:		destination structure
 *
 * Retrieve the lowest HCB.
 */
static int hcb_get_deref(const char *path, struct hcb *cb)
{
	int ret;

	if ((ret = hcb_get(path, cb)) < 0)
		return ret;
	if ((ret = hcb_deref(cb)) < 0)
		return ret;

	return 0;
}

/**
 * hcb_update - write HCB
 * @cb:	data
 *
 * Write back the HCB with possibly changed data. hcb_put() is called
 * afterwards because that's what is usually intended.
 */
static int hcb_update(struct hcb *cb)
{
	int ret;

	if (cb->fd < 0) {
		/* When this HCB was created using hcb_new() */
		cb->fd = openat(root_fd, at(cb->path), O_RDWR | O_CREAT |
		         O_EXCL, S_IRUGO | S_IWUSR);
		if (cb->fd < 0)
			return -errno;
	}

	if (lock_write(cb->fd) < 0) {
		ret = -errno;
		close(cb->fd);
		return ret;
	}

	ret = ll_hcb_write(cb->path, &cb->ll, cb->fd);
	hcb_put(cb);
	return ret;
}

/**
 * hcb_lookup - shortcut for hcb_get()+hcb_put()
 * @path:	virtual path
 * @cb:		destination structure
 *
 * Do a standard HCB lookup with hardlink following.
 */
static int hcb_lookup(const char *path, struct hcb *cb)
{
	int ret;

	if ((ret = hcb_get(path, cb)) < 0)
		return ret;

	hcb_put(cb);
	return 0;
}

/**
 * hcb_lookup_deref - shortcut for hcb_get_deref()+hcb_put()
 * @path:	virtual path
 * @cb:		destination structure
 *
 * Do a standard HCB lookup with hardlink following.
 */
static int hcb_lookup_deref(const char *path, struct hcb *cb)
{
	int ret;

	if ((ret = hcb_get_deref(path, cb)) < 0)
		return ret;

	hcb_put(cb);
	return 0;
}

/**
 * hcb_lookup_readdir -
 * @dir:	working directory
 * @name:	file
 * @info:		destination structure
 *
 * Combines the working directory @dir with @name (to form an absolute path),
 * then retrieves the HCB.
 */
static int hcb_lookup_readdir(const char *dir, const char *name,
    struct hcb *info)
{
	char path[PATH_MAX];
	int ret;

	/*
	 * Ensure that @path does not have two leading slashes or
	 * the *at() logic does not do the right thing.
	 */
	if (dir[1] == '\0') {
		/*
		 * First character is always a slash, so if the second one is
		 * '\0', it must be "/". I am trying to optimize here.
		 */
		path[0] = '/';
		strlcpy(&path[1], name, sizeof(path) - 1);
		ret = strlen(name) + 1;
	} else {
		ret = snprintf(path, sizeof(path), "%s/%s", dir, name);
	}

	if (ret >= sizeof(path))
		return -ENAMETOOLONG;
	if ((ret = hcb_get_deref(path, info)) < 0)
		return ret;
	hcb_put(info);
	return 0;
}

static __attribute__((pure)) bool is_resv_name(const char *name)
{
	return strncmp(name, HCB_PREFIX, HCB_PREFIX_LEN) == 0 ||
	       strncmp(name, HL_DNODE_PREFIX, HL_DNODE_PREFIX_LEN) == 0 ||
	       strncmp(name, HL_INODE_PREFIX, HL_INODE_PREFIX_LEN) == 0 ||
	       strcmp(name, HCB_PREFIX1) == 0;
}

static __attribute__((pure)) bool is_resv(const char *path)
{
	const char *file = strrchr(path, '/');
	if (file++ == NULL)
		should_never_happen();
	return is_resv_name(file);
}

/**
 * supports_owners - check whether @path can do that
 * @path:	path to existing file
 * @uid:	uid to change to (used for figuring out)
 * @gid:	gid to change to
 * @restore:	restore permissions after check
 *
 * This has to be looked up on a per-path basis, because it is possible to
 * mount a filesystem supporting permissions on a directory on a filesystem
 * that does not, as in, for example, the following case:
 * 	mount -t vfat /dev/foo /mnt
 * 	mount -t xfs  /dev/bar /mnt/sub
 * 	mount.posixovl /mnt
 *
 * Note that on a filesystem which supports owners, our fchownat() will
 * always succeed (or always fail), because the kernel checks for
 * capability rather than FSUID. (Good thing.)
 */
static bool __supports_owners(const char *path, uid_t uid,
    gid_t gid, bool restore)
{
	struct stat orig_sb, new_sb;
	uid_t work_uid = -1;
	gid_t work_gid = -1;

	if (fstatat(root_fd, at(path), &orig_sb, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat");
		return false;
	}

	if (uid == -1)
		work_uid = orig_sb.st_uid;
	else if (orig_sb.st_uid != uid)
		work_uid = uid;
	else if (uid == 0)
		work_uid = -2;
	else
		should_not_happen();

	if (gid == -1)
		work_gid = orig_sb.st_gid;
	else if (orig_sb.st_gid != gid)
		work_gid = gid;
	else if (uid == 0)
		work_gid = -2;
	else
		should_not_happen();

	if (fchownat(root_fd, at(path), work_uid, work_gid,
	    AT_SYMLINK_NOFOLLOW) < 0)
		return false;
	if (fstatat(root_fd, at(path), &new_sb, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat");
		return false;
	}

	if (restore)
		if (fchownat(root_fd, at(path), orig_sb.st_uid,
		    orig_sb.st_gid, AT_SYMLINK_NOFOLLOW) < 0)
			should_not_happen();

	return new_sb.st_uid == work_uid && new_sb.st_gid == work_gid;
}

static bool supports_owners(const char *path, uid_t uid,
    gid_t gid, bool restore)
{
	if (assume_vfat)
		return false;
	return __supports_owners(path, uid, gid, restore);
}

/**
 * supports_permissions - check whether @path can do that
 * @path:	existing path to file
 *
 * Does not restore the original mode.
 */
static bool __supports_permissions(const char *path)
{
	struct stat orig_sb, new_sb;
	mode_t work_mode;

	if (fstatat(root_fd, at(path), &orig_sb, AT_SYMLINK_NOFOLLOW) < 0) {
		/* literally BUG() */
		perror("fstatat");
		return false;
	}

	/* Pick some magic */
	work_mode = (orig_sb.st_mode ^ S_IRUSR ^ S_IXGRP) & ~S_IROTH;

	if (fchmodat(root_fd, at(path), work_mode, AT_SYMLINK_NOFOLLOW) < 0)
		return false;
	if (fstatat(root_fd, at(path), &new_sb, AT_SYMLINK_NOFOLLOW) < 0) {
		perror("fstatat");
		return false;
	}
	return new_sb.st_mode == work_mode;
}

static bool supports_permissions(const char *path)
{
	if (assume_vfat)
		return false;
	return __supports_permissions(path);
}

/**
 * @read_ptr:	original to-disk filename
 *
 * Encode all the special characters that are invalid to use on VFAT by
 * substituting each by "%(xx)", where xx is the textual hexadecimal
 * representation. Returns a pointer to an allocated memory block containing
 * the encoded result.
 */
static char *xfrm_to_disk(const char *read_ptr)
{
	unsigned int needed = 0;
	const char *next;
	char *out, *out_ptr;

	for (next = read_ptr; *next != '\0'; ++next)
		switch (*next) {
		case '\\':
		case ':':
		case '*':
		case '?':
		case '\"':
		case '<':
		case '>':
		case '|':
			needed += strlen("%(XX)");
			break;
		/* Path separator ('/') is not to be encoded! */
		default:
			++needed;
			break;
		}

	out = out_ptr = malloc(needed + 1);
	if (out == NULL)
		return NULL;

	do {
		next = strpbrk(read_ptr, "\\:*?\"<>|");
		if (next == NULL) {
			strcpy(out_ptr, read_ptr);
			out_ptr += strlen(read_ptr);
			break;
		} else if (read_ptr != next) {
			strncpy(out_ptr, read_ptr, next - read_ptr);
			out_ptr += next - read_ptr;
		}
		sprintf(out_ptr, "%%(%02X)", *next);
		out_ptr += strlen("%(XX)");
		read_ptr = next + 1;
	} while (*read_ptr != '\0');

	*out_ptr = '\0';
	return out;
}

static const unsigned char xfrm_table[] = {
	['0'] =  0, ['1'] =  1, ['2'] =  2, ['3'] =  3,
	['4'] =  4, ['5'] =  5, ['6'] =  6, ['7'] =  7,
	['8'] =  8, ['9'] =  9, ['A'] = 10, ['B'] = 11,
	['C'] = 12, ['D'] = 13, ['E'] = 14, ['F'] = 15,
};

/**
 * @read_ptr:	original on-disk filename
 *
 * Decode a name that has the %(xx) special sequences in it and return a
 * pointer to an allocated memory block with the result.
 */
static char *xfrm_from_disk(const char *read_ptr)
{
	const char *seek_ptr = read_ptr, *next;
	char *out = malloc(strlen(read_ptr) + 1), *out_ptr = out;

	if (out == NULL)
		return NULL;

	do {
		next = strstr(seek_ptr, "%(");
		if (next == NULL) {
			strcpy(out_ptr, read_ptr);
			out_ptr += strlen(read_ptr);
			break;
		}
		if (!isxdigit(next[2]) || !isxdigit(next[3]) ||
		    next[4] != ')') {
			seek_ptr = next + 1;
			continue;
		}
		strncpy(out_ptr, read_ptr, next - read_ptr);
		out_ptr += next - read_ptr;
		read_ptr = seek_ptr = next + strlen("%(XX)");
		*out_ptr++ = (xfrm_table[toupper(next[2])] << 4) |
		             xfrm_table[toupper(next[3])];
	} while (*read_ptr != '\0');

	*out_ptr = '\0';
	return out;
}

static int posixovl_chmod(const char *path, mode_t mode)
{
	struct hcb info;
	int ret;

	if (is_resv(path))
		return -ENOENT;
	ret = hcb_get_deref(path, &info);
	if (ret == -ENOENT_HCB) {
		if (supports_permissions(path))
			return retcode_int(fchmodat(root_fd, at(path), mode,
			       AT_SYMLINK_NOFOLLOW));
		if ((ret = hcb_new(path, &info, 1)) < 0)
			return ret;
		/* nlink already set (hcb_new() stat'ed @path) */
	} else if (ret < 0) {
		return ret;
	}

	info.ll.mode = mode;
	return hcb_update(&info);
}

static int posixovl1_chmod(const char *path, mode_t mode)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_chmod(xpath, mode);
	free(xpath);
	return ret;
}

static int posixovl_chown(const char *path, uid_t uid, gid_t gid)
{
	struct hcb info;
	int ret;

	if (is_resv(path))
		return -ENOENT;
	ret = hcb_get_deref(path, &info);
	if (ret == -ENOENT_HCB) {
		if (supports_owners(path, uid, gid, false))
			return retcode_int(fchownat(root_fd, at(path), uid,
			       gid, AT_SYMLINK_NOFOLLOW));
		if ((ret = hcb_new(path, &info, 1)) < 0)
			return ret;
		/* nlink already set (hcb_new() stat'ed @path) */
	} else if (ret < 0) {
		return ret;
	}

	if (uid != (uid_t)-1)
		info.ll.uid = uid;
	if (gid != (gid_t)-1)
		info.ll.gid = gid;
	return hcb_update(&info);
}

static int posixovl1_chown(const char *path, uid_t uid, gid_t gid)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_chown(xpath, uid, gid);
	free(xpath);
	return ret;
}

static int posixovl_close(const char *path, struct fuse_file_info *filp)
{
	return retcode_int(close(filp->fh));
}

static __attribute__((pure)) bool could_be_too_long(const char *path)
{
	/* Longest possible case is S_ISDIR: /path/.pxovl. */
	return strlen(path) + 1 + HCB_PREFIX_LEN >= PATH_MAX;
}

/**
 * parent_owner_match -
 * @path:	path, of which the parent is to be checked
 * @uid:	uid to test
 *
 * Checks whether @path's parent is owned by @uid.
 * @path denotes a path on the real volume, hence no HCB lookup here.
 */
static bool parent_owner_match(const char *path, uid_t uid)
{
	struct stat sb;
	int ret;

	ret = fstatat(root_fd, at(path), &sb, AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		should_not_happen();
		return false;
	}

	return sb.st_uid == uid;
}

static int posixovl_create(const char *path, mode_t mode,
    struct fuse_file_info *filp)
{
	const struct fuse_context *ctx;
	struct hcb cb;
	int fd, ret;

	if (is_resv(path))
		return -EPERM;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	fd  = openat(root_fd, at(path), filp->flags, mode);
	if (fd < 0)
		return -errno;

	filp->fh = fd;

	/*
	 * Default file permissions do not trigger creation of a HCB.
	 * We need (rather: want) a HCB if the fsuid is different from
	 * the owner of the underlying mount, if owners are not
	 * supported.
	 * Fuse oddity: @mode includes S_IFREG (contraty to mkdir())
	 */
	ctx = fuse_get_context();

	if (((mode & ~S_IWUSR) != (S_IFREG | (default_mode & ~S_IWUSR)) &&
	    !supports_permissions(path)) ||
	    (!parent_owner_match(path, ctx->uid) &&
	    !supports_owners(path, ctx->uid, ctx->gid, true))) {
		if ((ret = hcb_new(path, &cb, 0)) < 0)
			return 0;
		/* nlink already set (hcb_new() stat'ed @path) */
		cb.ll.mode = mode;
		cb.ll.uid  = ctx->uid;
		cb.ll.gid  = ctx->gid;
		hcb_update(&cb);
	}

	return 0;
}

static int posixovl1_create(const char *path, mode_t mode,
    struct fuse_file_info *filp)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_create(xpath, mode, filp);
	free(xpath);
	return ret;
}

static int posixovl_ftruncate(const char *path, off_t length,
    struct fuse_file_info *filp)
{
	return retcode_int(ftruncate(filp->fh, length));
}

/**
 * hl_demote - collapse S_IFHARDLNK into normal file
 * @l0_file:
 * @l0_hcb:
 * @l1_file:
 * @l1_hcb:
 *
 * Unlink the L0 files and move the L1 ones into L0's place.
 * Caller *must* ensure that the L1 HCB has nlink=1, or all other
 * hardlink slaves will break.
 */
static int hl_demote(const char *l0_file, const char *l0_hcb,
    const char *l1_file, const char *l1_hcb)
{
	int ret = 0;

	pthread_mutex_lock(&posixovl_protect);
	if (unlinkat(root_fd, at(l0_file), 0) < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return -errno;
	}
	unlinkat(root_fd, at(l0_hcb), 0);
	if (renameat(root_fd, at(l1_hcb), root_fd, at(l0_hcb)) < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		ret = -errno;
		fprintf(stderr, "%s: rename %s -> %s failed: %s\n",
		        __func__, l1_hcb, l0_hcb, strerror(errno));
		return ret;
	}
	if (renameat(root_fd, at(l1_file), root_fd, at(l0_file)) < 0) {
		ret = -errno;
		fprintf(stderr, "%s: rename %s -> %s failed: %s\n",
		        __func__, l1_file, l0_file, strerror(errno));
	}
	pthread_mutex_unlock(&posixovl_protect);
	return ret;
}

/**
 * hl_try_demote - try to collapse a one-link hardlink net into one file
 * @path:	real path
 *
 * Check if @path is a S_IFHARDLNK and if its link count is 1, demote the
 * four-file set (virtual file, L0 HCB, data file, L1 HCB) into a two-file
 * set (virtual + HCB).
 */
static int hl_try_demote(const char *path)
{
	struct hcb info_l0, info_l1;
	int ret;

	ret = hcb_lookup(path, &info_l0);
	if (ret == -ENOENT_HCB)
		return 0;
	if (ret < 0)
		return ret;
	if (!S_ISHARDLNK(info_l0.ll.mode))
		return 0;

	memcpy(&info_l1, &info_l0, sizeof(info_l0));
	if ((ret = hcb_deref(&info_l1)) < 0)
		return ret;
	hcb_put(&info_l1);
	if (info_l1.ll.nlink != 1)
		return 0;

	return hl_demote(path, info_l0.path, info_l0.ll.target, info_l1.path);
}

static int posixovl_getattr(const char *path, struct stat *sb)
{
	struct hcb info;
	int ret;

	if (is_resv(path))
		return -ENOENT;
	ret = hcb_lookup_deref(path, &info);
	if (ret < 0 && ret != -ENOENT_HCB && ret != -EACCES)
		return ret;
	memcpy(sb, &info.sb, sizeof(*sb));
	return 0;
}

static int posixovl1_getattr(const char *path, struct stat *sb)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_getattr(xpath, sb);
	free(xpath);
	return ret;
}

static int posixovl_getxattr(const char *path, const char *name,
    char *value, size_t size)
{
	return retcode_int(lgetxattr(at(path), name, value, size));
}

static int posixovl1_fgetattr(const char *path, struct stat *sb,
    struct fuse_file_info *filp)
{
	/*
	 * Need to use the normal getattr because we need to check for the
	 * HCB too, not just @filp->fh.
	 */
	return posixovl1_getattr(path, sb);
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

static int posixovl_fcopy(int dfd, const char *source)
{
	int sfd = open(source, O_RDONLY);
	ssize_t ret;
	char buffer[65536];

	if (sfd < 0)
		return -errno;
	while ((ret = read(sfd, buffer, sizeof(buffer))) > 0)
		if (write(dfd, buffer, ret) < 0) {
			ret = -errno;
			break;
		}
	return ret;
}

/**
 * The size of the inode type may be larger than that of the type that rand()
 * returns, so call rand() as often as needed to fill all bits.
 * Minus 1 is used because it may be a signed integer whose sign is never set.
 * So in the usual case of ino_t being 64 bit and int being 32 bit, we will
 * call rand() thrice.
 */
static ino_t make_inum(void)
{
	static const unsigned int advance =
		sizeof(__typeof__(rand())) * CHAR_BIT - 1;
	ino_t ino = 0;

	for (unsigned int b = 0; b < sizeof(ino) * CHAR_BIT; b += advance) {
		ino <<= advance;
		ino ^= rand();
	}
	return ino;
}

/**
 * hl_promote - transform state 0/1 file into hardlink master (state 2)
 * @l0_path:		path to real file
 * @orig_info:		L0 HCB
 * @l0_hcb_exists:	what it says
 */
static int hl_promote(const char *l0_path, const struct hcb *orig_info,
    bool l0_hcb_exists)
{
	char l1_path[PATH_MAX], l1_hcb[PATH_MAX];
	struct stat work_sb;
	struct hcb new_info;
	int fd, ret;

	/*
	 * Create a unique ID. Note that there may be underlying filesystems
	 * where inode numbers are dynamically generated. Hence they may
	 * overlap with posixovl IDs (encoded into the filename) from a
	 * previous mount, hence we rand() should the ID already exist.
	 */
	work_sb.st_ino = orig_info->sb.st_ino;
	do {
		snprintf(l1_path, sizeof(l1_path), "/" HL_DNODE_PREFIX "%lx",
			 static_cast(unsigned long, work_sb.st_ino));
		snprintf(l1_hcb, sizeof(l1_hcb), "/" HL_INODE_PREFIX "%lx",
			 static_cast(unsigned long, work_sb.st_ino));
		if (fstatat(root_fd, at(l1_path), &work_sb,
		    AT_SYMLINK_NOFOLLOW) == 0) {
			work_sb.st_ino = make_inum();
			continue;
		}
		if (errno == ENOENT)
			/* ok, can use this ID */
			break;
		return -errno;
	} while (true);

	/* Move L0 to L1 */
	ret = renameat(root_fd, at(l0_path), root_fd, at(l1_path));
	if (ret < 0)
		return -errno;

	/* move L0 HCB to L1 HCB */
	if (l0_hcb_exists) {
		ret = renameat(root_fd, at(orig_info->path),
		      root_fd, at(l1_hcb));
		if (ret < 0) {
			ret = -errno;
			goto out;
		}
		/* nlink already ok */
	} else {
		if ((ret = hcb_new(l1_path, &new_info, 0)) < 0)
			goto out;
		if ((ret = hcb_update(&new_info)) < 0)
			goto out;
	}

	/* initialize first link */
	if ((ret = hcb_new(l0_path, &new_info, 0)) < 0)
		goto out2;
	new_info.ll.mode  = S_IFHARDLNK;
	new_info.ll.nlink = 1;
	strlcpy(new_info.ll.new_target, l1_path, sizeof(new_info.ll.new_target));
	hcb_update(&new_info);

	/* instantiate first link into readdir visibility */
	fd = openat(root_fd, at(l0_path), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		goto out3;
	}
	if (hardlink_with_copy)
		posixovl_fcopy(fd, new_info.ll.new_target);
	close(fd);
	return 0;

 out3:
	unlinkat(root_fd, at(orig_info->path), 0);
 out2:
	if (l0_hcb_exists)
		renameat(root_fd, at(l1_hcb), root_fd, at(orig_info->path));
 out:
	renameat(root_fd, at(l1_path), root_fd, at(l0_path));
	return ret;
}

/**
 * hl_up_nlink - increase nlink count of hardlink master
 * @l1_path:	name of the L1 file
 *		(Could have used the L0 file, but using L1 saves a derefernce,
 *		which has already been performed in the caller anyway)
 */
static int hl_up_nlink(const char *l1_path)
{
	struct hcb cb;
	int ret;

	if ((ret = hcb_get(l1_path, &cb)) < 0)
		return ret;
	if (S_ISHARDLNK(cb.ll.mode))
		should_not_happen();
	else
		++cb.ll.nlink;
	return hcb_update(&cb);
}

/**
 * hl_drop - drop nlink count of hardlink master
 * @l1_path:	name of the L1 file
 *
 * Drop the nlink of the hardlink master by one, and if it reaches zero,
 * unlink the D-node.
 */
static int hl_drop(const char *l1_path)
{
	struct hcb cb;
	int ret;

	if ((ret = hcb_get(l1_path, &cb)) < 0)
		return ret;
	if (S_ISHARDLNK(cb.ll.mode)) {
		should_not_happen();
		hcb_put(&cb);
		return 0;
	}
	if (cb.ll.nlink == 0)
		should_not_happen();
	if (cb.ll.nlink == 1) {
		hcb_put(&cb);
		pthread_mutex_lock(&posixovl_protect);
		unlinkat(root_fd, at(l1_path), 0);
		unlinkat(root_fd, at(cb.path), 0);
		pthread_mutex_unlock(&posixovl_protect);
		return 0;
	}

	--cb.ll.nlink;
	return hcb_update(&cb);
}

/**
 * hl_instantiate - make (another) hardlink
 * @oldpath:
 * @newpath:
 */
static int hl_instantiate(const char *oldpath, const char *newpath)
{
	struct hcb cb_old, cb_new;
	int fd, ret;

	pthread_mutex_lock(&posixovl_protect);
	ret = hcb_lookup(oldpath, &cb_old);
	if (ret == -ENOENT_HCB || (ret == 0 && !S_ISHARDLNK(cb_old.ll.mode))) {
		/*
		 * If no HCB attached or if not a hardlink slave...
		 * Transform file from state 0/1 to 2.
		 */
		if ((ret = hl_promote(oldpath, &cb_old,
		    ret != -ENOENT_HCB)) < 0)
			goto unlock_and_out;
		/*
		 * Relookup to get the dnode file path
		 */
		if ((ret = hcb_lookup(oldpath, &cb_old)) < 0)
			goto unlock_and_out;
	} else if (ret < 0) {
		pthread_mutex_unlock(&posixovl_protect);
		return -errno;
	}

	pthread_mutex_unlock(&posixovl_protect);

	/* now we can do the Nth link */
	if ((ret = hl_up_nlink(cb_old.ll.target)) < 0)
		return ret;

	if ((ret = hcb_new(newpath, &cb_new, 0)) < 0)
		goto out;
	cb_new.ll.mode  = S_IFHARDLNK;
	cb_new.ll.nlink = 1;
	strlcpy(cb_new.ll.new_target, cb_old.ll.target,
	        sizeof(cb_new.ll.new_target));
	if ((ret = hcb_update(&cb_new)) < 0)
		goto out;

	fd = openat(root_fd, at(newpath), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		goto out2;
	}
	if (hardlink_with_copy)
		posixovl_fcopy(fd, cb_new.ll.new_target);
	close(fd);
	return 0;

 out2:
	unlinkat(root_fd, at(cb_new.path), 0);
 out:
	hl_drop(cb_old.ll.target);
	return ret;

 unlock_and_out:
	pthread_mutex_unlock(&posixovl_protect);
	return ret;
}

static int posixovl_link(const char *oldpath, const char *newpath)
{
	int ret;

	if (is_resv(oldpath))
		return -ENOENT;
	if (is_resv(newpath))
		return -EPERM;
	if (could_be_too_long(oldpath) || could_be_too_long(newpath))
		return -ENAMETOOLONG;

	/*
	 * Kernel/FUSE already takes care of prohibiting hardlinking
	 * directories. We never get to see these.
	 */
	if (!assume_vfat) {
		ret = linkat(root_fd, at(oldpath), root_fd, at(newpath), 0);
		if (ret < 0 && errno != EPERM)
			return ret;
		else if (ret >= 0)
			return 0;
	}

	return hl_instantiate(oldpath, newpath);
}

static int posixovl1_link(const char *oldpath, const char *newpath)
{
	char *xoldpath = xfrm_to_disk(oldpath);
	char *xnewpath = xfrm_to_disk(newpath);
	int ret        = posixovl_link(xoldpath, xnewpath);
	free(xoldpath);
	free(xnewpath);
	return ret;
}

static int posixovl_listxattr(const char *path, char *list, size_t size)
{
	return retcode_int(llistxattr(at(path), list, size));
}

static int posixovl_mkdir(const char *path, mode_t mode)
{
	const struct fuse_context *ctx;
	struct hcb cb;
	int ret;

	if (is_resv(path))
		return -EPERM;
	if (could_be_too_long(path))
		return -ENAMETOOLONG;

	ret = mkdirat(root_fd, at(path), mode);
	if (ret < 0)
		return -errno;

	/* FUSE oddity: @mode does not include S_IFDIR */
	ctx = fuse_get_context();

	if (((mode & ~S_IWUSR) != ((default_mode & ~S_IWUSR) | S_IXUGO) &&
	    !supports_permissions(path)) ||
	    (!parent_owner_match(path, ctx->uid) &&
	    !supports_owners(path, ctx->uid, ctx->gid, true))) {
		if ((ret = hcb_new(path, &cb, 0)) < 0)
			return 0;
		/* nlink already set (hcb_new() stat'ed @path) */
		cb.ll.mode = S_IFDIR | mode;
		cb.ll.uid  = ctx->uid;
		cb.ll.gid  = ctx->gid;
		hcb_update(&cb);
	}

	return 0;
}

static int posixovl1_mkdir(const char *path, mode_t mode)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_mkdir(xpath, mode);
	free(xpath);
	return ret;
}

static int posixovl_mknod(const char *path, mode_t mode, dev_t rdev)
{
	const struct fuse_context *ctx;
	struct hcb info;
	int fd, ret;

	if (is_resv(path))
		return -EPERM;

	if (!assume_vfat) {
		ret = mknodat(root_fd, at(path), mode, rdev);
		if (ret < 0 && errno != EPERM)
			return ret;
		else if (ret >= 0)
			return 0;
	}

	/*
	 * The HCB is created first - since that one does not show up in
	 * readdir() and is not accessible either.
	 * Same goes for posixovl_symlink().
	 */
	if ((ret = hcb_new(path, &info, 0)) < 0)
		return ret;

	ctx = fuse_get_context();
	info.ll.mode  = mode;
	info.ll.nlink = 1;
	info.ll.uid   = ctx->uid;
	info.ll.gid   = ctx->gid;
	info.ll.rdev  = rdev;
	if ((ret = hcb_update(&info)) < 0)
		return ret;

	fd = openat(root_fd, at(path), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		unlinkat(root_fd, at(info.path), 0);
	}
	close(fd);
	return ret;
}

static int posixovl1_mknod(const char *path, mode_t mode, dev_t rdev)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_mknod(xpath, mode, rdev);
	free(xpath);
	return ret;
}

static int posixovl_open(const char *path, struct fuse_file_info *filp)
{
	struct hcb info;
	int fd, ret;

	if (is_resv(path))
		return -ENOENT;

	if ((filp->flags & O_ACCMODE) == O_WRONLY ||
	    (filp->flags & O_ACCMODE) == O_RDWR)
		if ((ret = hl_try_demote(path)) < 0)
			return ret;

	ret = hcb_lookup(path, &info);
	if (ret < 0 && ret != -ENOENT_HCB)
		return ret;
	if (ret == 0 && S_ISHARDLNK(info.ll.mode))
		fd = openat(root_fd, at(info.ll.target), filp->flags);
	else
		/*
		 * no need to handle non-regular files -- kernel and fuse do
		 * that for us.
		 */
		fd = openat(root_fd, at(path), filp->flags);

	if (fd < 0)
		return -errno;

	filp->fh = fd;
	return 0;
}

static int posixovl1_open(const char *path, struct fuse_file_info *filp)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_open(xpath, filp);
	free(xpath);
	return ret;
}

static int posixovl_read(const char *path, char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	return retcode_ssize(pread(filp->fh, buffer, size, offset));
}

static int posixovl_readdir(const char *path, void *buffer,
    fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *filp)
{
	const struct dirent *dentry;
	struct hcb info;
	int ret = 0;
	DIR *ptr;
	char *x;

	if (is_resv(path))
		return -ENOENT;
	/*
	 * Current working directory is root_fd (per posixovl_init()).
	 * Let's hope opendir(relative_path) works.
	 */
	if ((ptr = opendir(at(path))) == NULL)
		return -errno;

	while ((dentry = readdir(ptr)) != NULL) {
		if (is_resv_name(dentry->d_name))
			continue;
		ret = hcb_lookup_readdir(path, dentry->d_name, &info);
		if (ret < 0 && ret != -ENOENT_HCB && ret != -EACCES)
			break;
		ret = 0;
		x = xfrm_from_disk((char *)dentry->d_name);
		if ((*filldir)(buffer, x, &info.sb, 0) > 0)
			break;
		free(x);
	}

	closedir(ptr);
	return ret;
}

static int posixovl1_readdir(const char *path, void *buffer,
    fuse_fill_dir_t filldir, off_t offset, struct fuse_file_info *filp)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_readdir(xpath, buffer, filldir, offset, filp);
	free(xpath);
	return ret;
}

static int posixovl_readlink(const char *path, char *dest, size_t size)
{
	struct hcb info;
	int ret;

	if (is_resv(path))
		return -ENOENT;

	ret = readlinkat(root_fd, at(path), dest, size - 1);
	if (ret < 0 && errno != EINVAL) {
		return ret;
	} else if (ret >= 0) {
		dest[ret] = '\0';
		return 0;
	}

	ret = hcb_lookup_deref(path, &info);
	if (ret == -ENOENT_HCB)
		return -EINVAL; /* not a symlink */
	else if (ret < 0)
		return ret;
	if (!S_ISLNK(info.ll.mode))
		return -EINVAL; /* not a symbolic link */

	memset(dest, 0, size);
	strlcpy(dest, info.ll.target, size);
	return 0;
}

static int posixovl1_readlink(const char *path, char *dest, size_t size)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_readlink(xpath, dest, size);
	free(xpath);
	return ret;
}

static int posixovl_removexattr(const char *path, const char *name)
{
	return retcode_int(lremovexattr(path, name));
}

static int posixovl_rename(const char *oldpath, const char *newpath)
{
	char new_hcbpath[PATH_MAX];
	struct hcb old_info;
	int ret, ret_2;

	if (is_resv(oldpath))
		return -ENOENT;
	if (is_resv(newpath))
		return -EPERM;
	if (could_be_too_long(newpath))
		return -ENAMETOOLONG;

	ret = hcb_lookup(oldpath, &old_info);
	if (ret == -ENOENT_HCB || S_ISDIR(old_info.sb.st_mode))
		return retcode_int(renameat(root_fd, at(oldpath),
		       root_fd, at(newpath)));
	else if (ret < 0)
		return ret;

	if ((ret = real_to_hcb(new_hcbpath, newpath)) < 0)
		return ret;

	pthread_mutex_lock(&posixovl_protect);
	ret_2 = renameat(root_fd, at(oldpath), root_fd, at(newpath));
	if (ret_2 < 0) {
		ret = -errno;
		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}
	ret_2 = renameat(root_fd, at(old_info.path), root_fd, at(new_hcbpath));
	if (ret_2 < 0) {
		/* !@#$%^& - error. Need to rename old file back. */
		ret = -errno;
		if (renameat(root_fd, at(newpath), root_fd, at(oldpath)) < 0) {
			/* Even that failed. Keep new name, but kill HCB. */
			unlinkat(root_fd, at(old_info.path), 0);
			hcb_got_busted(old_info.path);
		}

		pthread_mutex_unlock(&posixovl_protect);
		return ret;
	}

	pthread_mutex_unlock(&posixovl_protect);
	return 0;
}

static int posixovl1_rename(const char *oldpath, const char *newpath)
{
	char *xoldpath = xfrm_to_disk(oldpath);
	char *xnewpath = xfrm_to_disk(newpath);
	int ret        = posixovl_rename(xoldpath, xnewpath);
	free(xoldpath);
	free(xnewpath);
	return ret;
}

static int posixovl_rmdir(const char *path)
{
	struct hcb info;
	int ret;

	if (is_resv(path))
		return -ENOENT;
	ret = hcb_lookup(path, &info);
	if (ret == 0 && unlinkat(root_fd, at(info.path), 0) < 0)
		return -errno;
	return retcode_int(unlinkat(root_fd, at(path), AT_REMOVEDIR));
}

static int posixovl1_rmdir(const char *path)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_rmdir(xpath);
	free(xpath);
	return ret;
}

static int posixovl_setxattr(const char *path, const char *name,
    const char *value, size_t size, int flags)
{
	return retcode_int(lsetxattr(at(path), name, value, size, flags));
}

static int posixovl_statfs(const char *path, struct statvfs *sb)
{
	if (fstatvfs(root_fd, sb) < 0)
		return -errno;
	sb->f_fsid = 0;
	return 0;
}

static int posixovl_symlink(const char *oldpath, const char *newpath)
{
	const struct fuse_context *ctx;
	struct hcb info;
	int fd, ret;

	if (is_resv(newpath))
		return -EPERM;

	if (!assume_vfat) {
		ret = symlinkat(oldpath, root_fd, at(newpath));
		if (ret < 0 && errno != EPERM)
			return -errno;
		else if (ret >= 0)
			return 0;
	}

	/* symlink() not supported on @path */
	if ((ret = hcb_new(newpath, &info, 0)) < 0)
		return ret;

	ctx = fuse_get_context();
	info.ll.mode  = S_IFSOFTLNK;
	info.ll.nlink = 1;
	info.ll.uid   = ctx->uid;
	info.ll.gid   = ctx->gid;
	strlcpy(info.ll.new_target, oldpath, sizeof(info.ll.new_target));
	if ((ret = hcb_update(&info)) < 0)
		return ret;

	fd = openat(root_fd, at(newpath), O_WRONLY | O_CREAT | O_EXCL, 0);
	if (fd < 0) {
		ret = -errno;
		unlinkat(root_fd, at(info.path), 0);
	} else {
		close(fd);
	}

	return ret;
}

static int posixovl1_symlink(const char *oldpath, const char *newpath)
{
	char *xoldpath = xfrm_to_disk(oldpath);
	char *xnewpath = xfrm_to_disk(newpath);
	int ret        = posixovl_symlink(xoldpath, xnewpath);
	free(xoldpath);
	free(xnewpath);
	return ret;
}

static int posixovl_truncate(const char *path, off_t length)
{
	struct hcb info;
	int fd, ret;

	if (is_resv(path))
		return -ENOENT;
	if ((ret = hl_try_demote(path)) < 0)
		return ret;

	ret = hcb_lookup_deref(path, &info);
	if (ret < 0 && ret != -ENOENT_HCB)
		return -errno;
	else if (ret == 0 && !S_ISREG(info.ll.mode) && !S_ISDIR(info.ll.mode))
		/*
		 * A HCB was found. But truncating special
		 * files (e.g. /dev/zero) is invalid.
		 */
		return -EINVAL;

	ret = hcb_lookup(path, &info);
	if (ret < 0 && ret != -ENOENT_HCB)
		return ret;

	/*
	 * There is no ftruncateat(), so need to use openat()+ftruncate() here.
	 */
	if (ret == 0 && S_ISHARDLNK(info.ll.mode))
		fd = openat(root_fd, at(info.ll.target), O_WRONLY);
	else
		fd = openat(root_fd, at(path), O_WRONLY);

	if (fd < 0)
		return -errno;
	ret = 0;
	if (ftruncate(fd, length) < 0)
		ret = -errno;

	close(fd);
	return ret;
}

static int posixovl1_truncate(const char *path, off_t len)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_truncate(xpath, len);
	free(xpath);
	return ret;
}

static int posixovl_unlink(const char *path)
{
	struct hcb info;
	int ret, h_ret;

	if (is_resv(path))
		return -ENOENT;

	/*
	 * Need to unlink the real file first so that the potential case
	 * "HCB non-existent but real file existent" does not happen in
	 * readdir().
	 */
	h_ret = hcb_lookup(path, &info);
	if (h_ret < 0 && h_ret != -ENOENT_HCB)
		return h_ret;

	ret = unlinkat(root_fd, at(path), 0);
	if (ret < 0)
		return -errno;

	if (h_ret == 0) {
		unlinkat(root_fd, at(info.path), 0);
		if (S_ISHARDLNK(info.ll.mode))
			hl_drop(info.ll.target);
	}

	return 0;
}

static int posixovl1_unlink(const char *path)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_unlink(xpath);
	free(xpath);
	return ret;
}

static int posixovl_utimens(const char *path, const struct timespec *ts)
{
	struct hcb info;
	int ret;
#ifndef HAVE_UTIMENSAT
	struct timeval tv[2];
#endif

	if (is_resv(path))
		return -ENOENT;

#ifndef HAVE_UTIMENSAT
	tv[0].tv_sec  = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec  = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;
#endif

	ret = hcb_lookup(path, &info);
	if (ret < 0 && ret != -ENOENT_HCB)
		return ret;

	/*
	 * The time attributes are always applied to the plain file,
	 * never the special file.
	 * (Until a filesystem that cannot store times comes along.)
	 * In case of S_IFHARDLNK, the .pxovd. file carries the stamp.
	 */

#ifndef HAVE_UTIMENSAT
	if (ret == 0 && S_ISHARDLNK(info.ll.mode))
		ret = futimesat(root_fd, at(info.ll.target), tv);
	else
		ret = futimesat(root_fd, at(path), tv);
#else
	if (ret == 0 && S_ISHARDLNK(info.ll.mode))
		ret = utimensat(root_fd, at(info.ll.target),
		      ts, AT_SYMLINK_NOFOLLOW);
	else
		ret = utimensat(root_fd, at(path), ts, AT_SYMLINK_NOFOLLOW);
#endif
	return retcode_int(ret);
}

static int posixovl1_utimens(const char *path, const struct timespec *ts)
{
	char *xpath = xfrm_to_disk(path);
	int ret     = posixovl_utimens(xpath, ts);
	free(xpath);
	return ret;
}

static int posixovl_write(const char *path, const char *buffer, size_t size,
    off_t offset, struct fuse_file_info *filp)
{
	return retcode_ssize(pwrite(filp->fh, buffer, size, offset));
}

static bool user_allow_other(void)
{
	bool ret = false;
	char buf[64];
	FILE *fp;

	if ((fp = fopen("/etc/fuse.conf", "r")) == NULL)
		return false;
	while (fgets(buf, sizeof(buf), fp) != NULL)
		/* no fancy line ending checks or anything */
		if (strncmp(buf, "user_allow_other",
		    sizeof("user_allow_other") - 1) == 0) {
			ret = true;
			break;
		}

	fclose(fp);
	return ret;
}

static const struct fuse_operations posixovl_ops = {
	.chmod       = posixovl1_chmod,
	.chown       = posixovl1_chown,
	.create      = posixovl1_create,
	.fgetattr    = posixovl1_fgetattr,
	.ftruncate   = posixovl_ftruncate,
	.getattr     = posixovl1_getattr,
	.getxattr    = posixovl_getxattr,
	.init        = posixovl_init,
	.link        = posixovl1_link,
	.listxattr   = posixovl_listxattr,
	.mkdir       = posixovl1_mkdir,
	.mknod       = posixovl1_mknod,
	.open        = posixovl1_open,
	.read        = posixovl_read,
	.readdir     = posixovl1_readdir,
	.readlink    = posixovl1_readlink,
	.release     = posixovl_close,
	.removexattr = posixovl_removexattr,
	.rename      = posixovl1_rename,
	.rmdir       = posixovl1_rmdir,
	.setxattr    = posixovl_setxattr,
	.statfs      = posixovl_statfs,
	.symlink     = posixovl1_symlink,
	.truncate    = posixovl1_truncate,
	.unlink      = posixovl1_unlink,
	.utimens     = posixovl1_utimens,
	.write       = posixovl_write,
};

static void usage(const char *p)
{
	fprintf(stderr,
	        "Usage: %s [-FH] [-S source] mountpoint [-- fuseoptions]\n", p);
	exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
	char **aptr, **new_argv;
	int new_argc = 0, original_wd, c;
	char xargs[256];

	while ((c = getopt(argc, argv, "1FHS:")) > 0) {
		switch (c) {
			case '1':
				single_threaded = true;
				break;
			case 'F':
				assume_vfat = true;
				break;
			case 'H':
				hardlink_with_copy = true;
				break;
			case 'S':
				root_dir = optarg;
				break;
			default:
				usage(*argv);
				return EXIT_FAILURE;
		}
	}

	if (argv[optind] == NULL)
		usage(*argv);
	if (root_dir == NULL)
		root_dir = argv[optind];

	umask(0);
	if ((root_fd = open(root_dir, O_DIRECTORY)) < 0) {
		fprintf(stderr, "Could not open(\"%s\"): %s\n",
		        root_dir, strerror(errno));
		return EXIT_FAILURE;
	}

	original_wd = open(".", O_DIRECTORY);

	new_argv = malloc(sizeof(char *) * (argc + 5 - optind));
	new_argv[new_argc++] = argv[0];
#ifdef HAVE_JUST_FUSE_2_6_5
	snprintf(xargs, sizeof(xargs),
	         "-oattr_timeout=0,default_permissions,use_ino,nonempty,dev,"
	         "fsname=posix-overlay(%s)", root_dir);
#else
	snprintf(xargs, sizeof(xargs),
	         "-oattr_timeout=0,default_permissions,use_ino,nonempty,dev,"
	         "fsname=posix-overlay(%s),subtype=posixovl", root_dir);
#endif
	new_argv[new_argc++] = xargs;

	if (user_allow_other())
		new_argv[new_argc++] = "-oallow_other";
	if (single_threaded)
		new_argv[new_argc++] = "-s";

	for (aptr = &argv[optind]; *aptr != NULL; ++aptr)
		new_argv[new_argc++] = *aptr;

	new_argv[new_argc] = NULL;
	c = fuse_main(new_argc, (char **)new_argv, &posixovl_ops, NULL);
	if (fchdir(original_wd) < 0)
		/* ignore */{}
	return c;
}
