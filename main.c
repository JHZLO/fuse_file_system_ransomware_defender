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
#include <pthread.h>
#include <math.h>

// 읽기 전용 확장자 설정
#define READ_ONLY_EXTENSIONS ".mp3", ".pdf"
#define MAX_WRITE_SIZE 1048576 // 1MB
#define MAX_WRITE_COUNT 50
#define TIME_WINDOW 60
#define MAX_FILES 100

// 파일 엔트로피 저장을 위한 구조체 및 배열
typedef struct {
    char path[PATH_MAX];
    double entropy;
} FileEntropy;

static int base_fd = -1;
static time_t last_write_time = 0;
static int write_count = 0;
static FileEntropy file_entropy_log[MAX_FILES];
static int entropy_log_index = 0;
pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;

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

// 파일 엔트로피 저장
void log_file_entropy(const char *path, double entropy) {
    pthread_mutex_lock(&entropy_lock);
    int found = 0;
    for (int i = 0; i < entropy_log_index; i++) {
        if (strcmp(file_entropy_log[i].path, path) == 0) {
            file_entropy_log[i].entropy = entropy;
            found = 1;
            break;
        }
    }
    if (!found && entropy_log_index < MAX_FILES) {
        strncpy(file_entropy_log[entropy_log_index].path, path, PATH_MAX);
        file_entropy_log[entropy_log_index].entropy = entropy;
        entropy_log_index++;
    }
    pthread_mutex_unlock(&entropy_lock);
}

// 이전 엔트로피 가져오기
double get_previous_entropy(const char *path) {
    pthread_mutex_lock(&entropy_lock);
    for (int i = 0; i < entropy_log_index; i++) {
        if (strcmp(file_entropy_log[i].path, path) == 0) {
            pthread_mutex_unlock(&entropy_lock);
            return file_entropy_log[i].entropy;
        }
    }
    pthread_mutex_unlock(&entropy_lock);
    return -1.0; // 이전 기록 없음
}

// ransomware 의심 활동 감지
static int detect_ransomware_activity(size_t size) {
    time_t current_time;
    time(&current_time);

    if (current_time - last_write_time <= TIME_WINDOW) {
        write_count++;
        if (write_count > MAX_WRITE_COUNT) {
            return 1; // 너무 많은 쓰기 작업
        }
    } else {
        write_count = 1; // 쓰기 작업 카운트 초기화
    }

    if (size > MAX_WRITE_SIZE) {
        return 1; // 파일 크기가 너무 큼
    }

    last_write_time = current_time;
    return 0; // 정상 쓰기
}

// 읽기 전용 확장자 확인 함수
static int is_read_only(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext && (strcmp(ext, ".mp3") == 0 || strcmp(ext, ".pdf") == 0)) {
        return 1; // 읽기 전용 확장자
    }
    return 0; // 읽기/쓰기 가능
}

// 상대 경로로 변환 함수
static void get_relative_path(const char *path, char *relpath) {
    if (strcmp(path, "/") == 0 || strcmp(path, "") == 0) {
        strcpy(relpath, ".");
    } else {
        if (path[0] == '/')
            path++;
        strncpy(relpath, path, PATH_MAX);
    }
}

// `getattr` 함수: 파일 속성 가져오기
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void)fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    if (is_read_only(relpath)) {
        stbuf->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH); // 쓰기 권한 제거
    }

    return 0;
}

// `readdir` 함수: 디렉토리 내용 읽기
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
    if (dp == NULL) {
        close(fd);
        return -errno;
    }

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
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

// `write` 함수: 엔트로피 감지 및 ransomware 방지
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (is_read_only(relpath)) {
        return -EACCES; // 읽기 전용 파일에 대한 쓰기 차단
    }

    double new_entropy = calculate_entropy(buf, size);
    if (detect_ransomware_activity(size)) {
        fprintf(stderr, "Suspicious write activity detected: %s\n", path);
        return -EIO; // 쓰기 작업 차단
    }

    log_file_entropy(path, new_entropy);

    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        return -errno;

    return res;
}

// FUSE 연산자 구조체
static const struct fuse_operations myfs2_oper = {
        .getattr = myfs_getattr,
        .readdir = myfs_readdir,
        .write   = myfs_write,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (mountpoint == NULL) {
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
