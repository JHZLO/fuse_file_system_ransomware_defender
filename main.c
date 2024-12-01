#define FUSE_USE_VERSION 35

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
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

// 파일 엔트로피 저장을 위한 구조체 및 배열
typedef struct {
    char path[PATH_MAX];
    double entropy;
} FileEntropy;

typedef struct {
    const char *ext;
    double threshold;
} FileThreshold;

// 확장자별 임계값
const FileThreshold thresholds[] = {
        {".txt", 2.5},
        {".docx", 1.2},
        {".doc", 1.2},
        {".dll", 0.8},
        {".mp3", 0.5},
        {".csv", 1.5},
        {".jpg", 0.8},
        {".pptx", 1.5},
        {".pdf", 1.0},
        {".json", 1.0},
        {".log", 1.2},
        {".xlsx", 1.5},
        {".xls", 1.5},
        {".exe", 0.8},
        {".bmp", 0.8},
        {".zip", 0.5},
        {".svg", 1.0},
        {".html", 1.2},
        {".c", 1.0},
        {".cpp", 1.0},
        {".py", 1.0},
        {".tmp", 1.0},
        {".hwp", 1.5},
        {".hwpx", 1.5},
        {".db", 0.8},
        {".ppt", 1.5},
        {".old", 1.0},
        {".png", 0.8},
        {".mp4", 0.5},
        {NULL, 1.0}
};

#define MAX_FILES 100
static FileEntropy file_entropy_log[MAX_FILES];
static int entropy_log_index = 0;
static int base_fd = -1;
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

double get_threshold_by_extension(const char *path) {
    const char *ext = strrchr(path, '.'); // 확장자 찾기
    if (ext) {
        for (size_t i = 0; thresholds[i].ext != NULL; i++) {
            if (strcmp(ext, thresholds[i].ext) == 0) {
                return thresholds[i].threshold;
            }
        }
    }
    return 1.0; // 기본 임계값
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
    char relpath[PATH_MAX];
    get_relative_path(path, relpath); // 상대 경로로 변환

    pthread_mutex_lock(&entropy_lock);
    for (int i = 0; i < entropy_log_index; i++) {
        if (strcmp(file_entropy_log[i].path, relpath) == 0) {
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

// 마운트 이전의 시점에 대한 파일 엔트로피 기록
void initialize_entropy_log(const char *mountpoint) {
    DIR *dp = opendir(mountpoint);
    if (!dp) {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char filepath[PATH_MAX];
    char relpath[PATH_MAX];

    while ((entry = readdir(dp)) != NULL) {
        // 현재 디렉토리 및 상위 디렉토리는 건너뜀
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, PATH_MAX, "%s/%s", mountpoint, entry->d_name);

        struct stat st;
        if (stat(filepath, &st) == -1) {
            perror("stat");
            continue;
        }

        // 파일인 경우 엔트로피 계산
        if (S_ISREG(st.st_mode)) {
            FILE *file = fopen(filepath, "rb");
            if (!file) {
                perror("fopen");
                continue;
            }

            char *buffer = malloc(st.st_size);
            if (!buffer) {
                perror("malloc");
                fclose(file);
                continue;
            }

            size_t bytesRead = fread(buffer, 1, st.st_size, file);
            fclose(file);

            if (bytesRead > 0) {
                // 상대 경로로 변환
                snprintf(relpath, PATH_MAX, "/%s", entry->d_name);
                get_relative_path(relpath, relpath); // 상대 경로 변환
                double entropy = calculate_entropy(buffer, bytesRead);
                log_file_entropy(relpath, entropy);
                fprintf(stderr, "[INIT] File: %s | Initial Entropy: %.2f\n", relpath, entropy);
            }

            free(buffer);
        }
    }

    closedir(dp);
}

// `getattr` 함수
static int myfs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
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
    (void) offset;
    (void) fi;
    (void) flags;

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


static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);  // 상대 경로 생성

    // 이전 엔트로피 가져오기
    double previous_entropy = get_previous_entropy(relpath);

    // 새 데이터의 엔트로피 계산
    double new_entropy = calculate_entropy(buf, size);

    double threshold = get_threshold_by_extension(path);

    // 로그 출력
    fprintf(stderr, "[LOG] File: %s | Previous Entropy: %.2f | New Entropy: %.2f | Diff: %.2f\n",
            relpath,
            (previous_entropy >= 0) ? previous_entropy : 0.0,
            new_entropy,
            (previous_entropy >= 0) ? fabs(new_entropy - previous_entropy) : new_entropy);
    fflush(stderr);

    // 엔트로피 차이 확인
    if (detect_entropy_increase(path, new_entropy, threshold)) {
        fprintf(stderr, "Entropy increase detected in file: %s\n", path);
        fflush(stderr);
        return -EACCES; // 작업 차단
    }

    // 새로운 엔트로피 기록
    log_file_entropy(relpath, new_entropy);

    // 기존 쓰기 작업 수행
    int res = pwrite(fi->fh, buf, size, offset);
    if (res == -1) res = -errno;

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
    (void) path;
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
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return -1;
    }

    // FUSE 인자를 수동으로 초기화
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    // 프로그램 이름 추가
    if (fuse_opt_add_arg(&args, argv[0]) == -1) {
        fprintf(stderr, "Failed to add program name to fuse args\n");
        fuse_opt_free_args(&args);
        return -1;
    }

    // "-f" 옵션 추가 (포그라운드 실행)
    if (fuse_opt_add_arg(&args, "-f") == -1) {
        fprintf(stderr, "Failed to add '-f' option to fuse args\n");
        fuse_opt_free_args(&args);
        return -1;
    }

    // 기존 인자 추가
    for (int i = 1; i < argc; i++) {
        if (fuse_opt_add_arg(&args, argv[i]) == -1) {
            fprintf(stderr, "Failed to add argument '%s' to fuse args\n", argv[i]);
            fuse_opt_free_args(&args);
            return -1;
        }
    }

    // 마운트 경로 확인
    char *mountpoint = realpath(argv[argc - 1], NULL);
    if (!mountpoint) {
        perror("realpath");
        fuse_opt_free_args(&args);
        return -1;
    }

    base_fd = open(mountpoint, O_RDONLY | O_DIRECTORY);
    if (base_fd == -1) {
        perror("open");
        free(mountpoint);
        fuse_opt_free_args(&args);
        return -1;
    }

    // 기존 파일의 초기 엔트로피 기록
    initialize_entropy_log(mountpoint);

    free(mountpoint);

    // FUSE 실행
    int ret = fuse_main(args.argc, args.argv, &myfs2_oper, NULL);

    // 자원 해제
    fuse_opt_free_args(&args);
    close(base_fd);

    return ret;
}


