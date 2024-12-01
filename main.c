#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>

#define READ_ONLY_EXT ".ro" // 읽기 전용 확장자
#define MAX_FILES 100

// 파일 엔트로피 저장 구조체
typedef struct {
    char path[PATH_MAX];
    double entropy;
} FileEntropy;

static int base_fd = -1;
FileEntropy file_entropy_log[MAX_FILES];
int entropy_log_index = 0;
pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;

// 확장자 검사 함수
static int is_read_only(const char *path) {
    const char *ext = strrchr(path, '.');
    return (ext && strcmp(ext, READ_ONLY_EXT) == 0);
}

// 상대 경로로 변환
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// 엔트로피 계산 함수
static double calculate_entropy(const char *data, size_t size) {
    if (size == 0) return 0.0;

    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[(unsigned char)data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double)counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

// Cross Entropy 탐지
static int detect_cross_entropy_anomaly(const char *path, const char *buf, size_t size, double threshold) {
    double current_entropy = calculate_entropy(buf, size);

    pthread_mutex_lock(&entropy_lock);
    double previous_entropy = -1.0;
    for (int i = 0; i < entropy_log_index; i++) {
        if (strcmp(file_entropy_log[i].path, path) == 0) {
            previous_entropy = file_entropy_log[i].entropy;
            break;
        }
    }

    if (previous_entropy < 0.0) { // 이전 엔트로피 기록 없음
        if (entropy_log_index < MAX_FILES) {
            strncpy(file_entropy_log[entropy_log_index].path, path, PATH_MAX);
            file_entropy_log[entropy_log_index].entropy = current_entropy;
            entropy_log_index++;
        }
        pthread_mutex_unlock(&entropy_lock);
        return 0; // 기록이 없으므로 이상 없음
    }

    double cross_entropy_diff = fabs(current_entropy - previous_entropy);
    pthread_mutex_unlock(&entropy_lock);

    if (cross_entropy_diff > threshold) {
        fprintf(stderr, "Cross Entropy Anomaly Detected: %s (Diff: %.2f)\n", path, cross_entropy_diff);
        return 1; // 이상 탐지
    }

    // 엔트로피 업데이트
    pthread_mutex_lock(&entropy_lock);
    for (int i = 0; i < entropy_log_index; i++) {
        if (strcmp(file_entropy_log[i].path, path) == 0) {
            file_entropy_log[i].entropy = current_entropy;
            break;
        }
    }
    pthread_mutex_unlock(&entropy_lock);
    return 0;
}

// `getattr` 함수
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void)fi;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    if (is_read_only(relpath)) {
        stbuf->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    }

    return 0;
}

// `readdir` 함수
static int myfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi,
                        enum fuse_readdir_flags flags) {
    (void)offset;
    (void)fi;
    (void)flags;

    DIR *dp;
    struct dirent *de;
    int fd;
    char relpath[PATH_MAX];

    get_relative_path(path, relpath);
    fd = openat(base_fd, relpath, O_RDONLY | O_DIRECTORY);
    if (fd == -1)
        return -errno;

    dp = fdopendir(fd);
    if (!dp) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st = {0};
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if (is_read_only(de->d_name)) {
            st.st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
        }

        if (filler(buf, de->d_name, &st, 0, 0))
            break;
    }

    closedir(dp);
    return 0;
}

// `open` 함수
static int myfs_open(const char *path, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (is_read_only(relpath) && (fi->flags & O_WRONLY || fi->flags & O_RDWR)) {
        return -EACCES;
    }

    int res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    int res;

    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}


// `write` 함수
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (is_read_only(relpath)) {
        return -EACCES;
    }

    if (detect_cross_entropy_anomaly(relpath, buf, size, 1.0)) {
        return -EACCES; // 이상 탐지 시 차단
    }

    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        return -errno;

    return res;
}

// `create` 함수
static int myfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (is_read_only(relpath)) {
        return -EACCES;
    }

    int res = openat(base_fd, relpath, fi->flags | O_CREAT, mode);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

// `unlink` 함수
static int myfs_unlink(const char *path) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (is_read_only(relpath)) {
        return -EACCES;
    }

    int res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// 기타 함수
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    (void)path;
    close(fi->fh);
    return 0;
}

static int myfs_mkdir(const char *path, mode_t mode) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_rmdir(const char *path) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    char relfrom[PATH_MAX], relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    if (is_read_only(relfrom)) {
        return -EACCES;
    }

    int res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    return 0;
}

static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    int res = utimensat(base_fd, relpath, tv, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// FUSE 연산자 구조체
static const struct fuse_operations myfs2_oper = {
        .getattr    = myfs_getattr,
        .readdir    = myfs_readdir,
        .open       = myfs_open,
        .create     = myfs_create,
        .read       = myfs_read,
        .write      = myfs_write,
        .release    = myfs_release,
        .unlink     = myfs_unlink,
        .mkdir      = myfs_mkdir,
        .rmdir      = myfs_rmdir,
        .rename     = myfs_rename,
        .utimens    = myfs_utimens,
};

// main 함수
int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (!mountpoint) {
        perror("realpath");
        return -1;
    }

    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open");
        free(mountpoint);
        return -1;
    }

    free(mountpoint);
    int ret = fuse_main(args.argc, args.argv, &myfs2_oper, NULL);
    close(base_fd);
    return ret;
}
