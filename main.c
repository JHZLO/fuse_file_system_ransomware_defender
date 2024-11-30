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
#include <time.h>
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
// trace last_write_time and write_count
static time_t last_write_time = 0;
static int write_count = 0;
static FileEntropy file_entropy_log[MAX_FILES];
static int entropy_log_index = 0;
pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;

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
    return -1.0; // 이전 기록이 없으면 -1 반환
}

// 엔트로피 차이를 통해 암호화 의심 탐지
int detect_entropy_increase(const char *path, double new_entropy, double threshold) {
    double previous_entropy = get_previous_entropy(path);
    if (previous_entropy < 0) return 0; // 이전 엔트로피 기록 없음
    return (new_entropy - previous_entropy) > threshold;
}

// 엔트로피 계산 함수
static double calculate_entropy(const char *data, size_t size) {
    if (size == 0) return 0.0;

    int counts[256] = {0};
    for (size_t i = 0; i < size; i++) {
        counts[(unsigned char) data[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double p = (double) counts[i] / size;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

static int detect_ransomware_activity(size_t size) {
    time_t current_time;
    time(&current_time);

    if (current_time - last_write_time <= TIME_WINDOW) {
        write_count++;
        if (write_count > MAX_WRITE_COUNT) {
            return 1; // too many write_count
        }
    } else {
        write_count = 1; // after few minute
    }

    if (size > MAX_WRITE_SIZE) {
        return 1;  // too big size
    }

    last_write_time = current_time;
    return 0; // normal write
}

// 확장자 검사 함수 (읽기 전용 파일 여부 확인)
static int is_read_only(const char *path) {
    const char *ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".mp3") == 0 || strcmp(ext, ".pdf") == 0)
            return 1;  // 읽기 전용
    }
    return 0;  // 읽기/쓰기 가능
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

// getattr 함수 구현
static int myfs_getattr(const char *path, struct stat *stbuf,
                        struct fuse_file_info *fi) {
    (void) fi;
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = fstatat(base_fd, relpath, stbuf, AT_SYMLINK_NOFOLLOW);
    if (res == -1)
        return -errno;

    // .mp3, .pdf 파일에 대해 쓰기 권한 제거
    if (is_read_only(relpath)) {
        stbuf->st_mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    }

    return 0;
}

// write 함수 구현 (읽기 전용 권한 부여)
static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // .mp3, .pdf 파일에 대한 쓰기 작업 차단
    if (is_read_only(relpath)) {
        return -EACCES;
    }

    // 새로운 엔트로피 계산
    double new_entropy = calculate_entropy(buf, size);

    // 엔트로피 증가 탐지 (임계값 설정: 1.0)
    if (detect_entropy_increase(path, new_entropy, 1.0)) {
        fprintf(stderr, "Entropy increase detected in file: %s\n", path);
        return -EACCES; // 작업 차단
    }

    // 엔트로피 기록 업데이트
    log_file_entropy(path, new_entropy);

    // 비정상적인 쓰기 작업 감지 (예: 크기나 빈도가 과도하게 많을 경우)
    if (detect_ransomware_activity(size)) {
        printf("Suspicious write activity detected!\n");
        return -EIO;  // 비정상적인 쓰기 거부
    }

    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}

// unlink 함수 구현 (읽기 전용 파일 삭제 차단)
static int myfs_unlink(const char *path) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    // .mp3, .pdf 파일 삭제 차단
    if (is_read_only(relpath)) {
        return -EACCES;
    }

    int res = unlinkat(base_fd, relpath, 0);
    if (res == -1)
        return -errno;

    return 0;
}

// release 함수 구현
static int myfs_release(const char *path, struct fuse_file_info *fi) {
    close(fi->fh);
    return 0;
}

// mkdir 함수 구현
static int myfs_mkdir(const char *path, mode_t mode) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = mkdirat(base_fd, relpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

// rmdir 함수 구현
static int myfs_rmdir(const char *path) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    res = unlinkat(base_fd, relpath, AT_REMOVEDIR);
    if (res == -1)
        return -errno;

    return 0;
}

// rename 함수 구현 (읽기 전용 파일의 이름 변경 차단)
static int myfs_rename(const char *from, const char *to, unsigned int flags) {
    int res;
    char relfrom[PATH_MAX];
    char relto[PATH_MAX];
    get_relative_path(from, relfrom);
    get_relative_path(to, relto);

    // 읽기 전용 파일의 이름 변경 차단
    if (is_read_only(relfrom)) {
        return -EACCES;
    }

    res = renameat(base_fd, relfrom, base_fd, relto);
    if (res == -1)
        return -errno;

    return 0;
}

// utimens 함수 구현
static int myfs_utimens(const char *path, const struct timespec tv[2],
                        struct fuse_file_info *fi) {
    int res;
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);

    if (fi != NULL && fi->fh != 0) {
        res = futimens(fi->fh, tv);
    } else {
        res = utimensat(base_fd
