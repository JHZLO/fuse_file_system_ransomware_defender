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
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>

// 미끼파일
#define HONEYPOT_FILENAME "h_o_nne_y_p_o_t.txt"
#define HONEYPOT_CONTENT "This is a honeypot file. Do not access."

#define READ_ONLY_EXTENSIONS ".mp3", ".pdf"
#define MAX_FILES 100
#define HEADER_SIZE 4
#define MAX_WRITE_SIZE 1048576 // 1MB
#define MAX_WRITE_COUNT 50
#define TIME_WINDOW 60

// 예상되는 헤더 (매직 넘버) 값들
#define PNG_HEADER    { 0x89, 0x50, 0x4E, 0x47 }  // PNG 파일 헤더
#define JPG_HEADER    { 0xFF, 0xD8, 0xFF, 0xE0 }  // JPEG 파일 헤더
#define XLSX_HEADER   { 0x50, 0x4B, 0x03, 0x04 }  // xlsx 파일 헤더
#define PPTX_HEADER   { 0x50, 0x4B, 0x03, 0x04 }  // pptx 파일 헤더
#define HWP_HEADER    { 0xED, 0xAB, 0xEE, 0xDB }  // hwp 파일 헤더
#define DOCX_HEADER   { 0x50, 0x4B, 0x03, 0x04 }  // docx 파일 헤더
#define DOC_HEADER    { 0xD0, 0xCF, 0x11, 0xE0 }  // doc 파일 헤더
#define MP4_HEADER    { 0x00, 0x00, 0x00, 0x18 }  // mp4 파일 헤더
#define ZIP_HEADER    { 0x50, 0x4B, 0x03, 0x04 }  // zip 파일 헤더
#define SQLITE_HEADER { 0x53, 0x51, 0x4C, 0x69 }  // sqlite 파일 헤더

// 미끼 파일의 절대 경로
static char honeypot_path[PATH_MAX];

// Trace variables
static time_t last_write_time = 0;
static int write_count = 0;

// File entropy tracking
typedef struct {
    char path[PATH_MAX];
    double entropy;
} FileEntropy;

static FileEntropy file_entropy_log[MAX_FILES];
static int entropy_log_index = 0;
static int base_fd = -1;

pthread_mutex_t entropy_lock = PTHREAD_MUTEX_INITIALIZER;

// Thresholds for entropy
typedef struct {
    const char *ext;
    double threshold;
} FileThreshold;

const FileThreshold thresholds[] = {
        {".txt",  2.5},
        {".docx", 1.5},
        {".doc",  1.2},
        {".dll",  0.5},
        {".mp3",  0.5},
        {".csv",  1.5},
        {".jpg",  0.5},
        {".pptx", 1.5},
        {".pdf",  1.0},
        {".json", 1.0},
        {".log",  1.2},
        {".xlsx", 1.5},
        {".xls",  1.5},
        {".exe",  0.5},
        {".bmp",  0.5},
        {".zip",  0.5},
        {".svg",  1.0},
        {".html", 1.5},
        {".c",    1.0},
        {".cpp",  1.0},
        {".py",   1.0},
        {".tmp",  1.0},
        {".hwp",  1.5},
        {".hwpx", 1.5},
        {".db",   0.5},
        {".ppt",  1.5},
        {".old",  1.0},
        {".png",  0.5},
        {".mp4",  0.5},
        {NULL,    1.0}
};

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

// 미끼 파일을 연 프로세스 종료
void terminate_ransomware_process(const char *path) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("opendir /proc");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        // 숫자로 된 디렉토리만 탐색 (프로세스 ID)
        if (entry->d_type != DT_DIR || !isdigit(entry->d_name[0]))
            continue;

        char fd_path[PATH_MAX];
        snprintf(fd_path, PATH_MAX, "/proc/%s/fd", entry->d_name);

        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            if (fd_entry->d_type != DT_LNK)
                continue;

            char link_target[PATH_MAX];
            char full_fd_path[PATH_MAX];
            snprintf(full_fd_path, PATH_MAX, "%s/%s", fd_path, fd_entry->d_name);

            ssize_t len = readlink(full_fd_path, link_target, PATH_MAX - 1);
            if (len != -1) {
                link_target[len] = '\0';

                // 미끼 파일을 연 프로세스 확인
                if (strcmp(link_target, path) == 0) {
                    pid_t pid = atoi(entry->d_name);
                    fprintf(stderr, "Terminating process %d for accessing honeypot file: %s\n", pid, path);
                    kill(pid, SIGKILL); // 프로세스 강제 종료
                }
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
}

// 미끼 파일 생성 함수
void create_honeypot_file(const char *mountpoint) {
    snprintf(honeypot_path, PATH_MAX, "%s/%s", mountpoint, HONEYPOT_FILENAME);

    FILE *honeypot_file = fopen(honeypot_path, "w");
    if (!honeypot_file) {
        perror("Failed to create honeypot file");
        return;
    }

    if (fwrite(HONEYPOT_CONTENT, 1, strlen(HONEYPOT_CONTENT), honeypot_file) != strlen(HONEYPOT_CONTENT)) {
        perror("Failed to write to honeypot file");
    }
    fclose(honeypot_file);

    fprintf(stderr, "Honeypot file created at: %s\n", honeypot_path);
}

// 확장자에 맞는 헤더 검증 함수
int check_header_for_extension(const char *path, const unsigned char *data) {
    if (strstr(path, ".png") != NULL) {
        unsigned char png_header[] = PNG_HEADER;
        if (memcmp(data, png_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 PNG 헤더
        }
    } else if (strstr(path, ".jpg") != NULL || strstr(path, ".jpeg") != NULL) {
        unsigned char jpg_header[] = JPG_HEADER;
        if (memcmp(data, jpg_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 JPEG 헤더
        }
    } else if (strstr(path, ".xlsx") != NULL) {
        unsigned char xlsx_header[] = XLSX_HEADER;
        if (memcmp(data, xlsx_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 xlsx 헤더
        }
    } else if (strstr(path, ".pptx") != NULL) {
        unsigned char pptx_header[] = PPTX_HEADER;
        if (memcmp(data, pptx_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 pptx 헤더
        }
    } else if (strstr(path, ".hwp") != NULL) {
        unsigned char hwp_header[] = HWP_HEADER;
        if (memcmp(data, hwp_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 hwp 헤더
        }
    } else if (strstr(path, ".docx") != NULL) {
        unsigned char docx_header[] = DOCX_HEADER;
        if (memcmp(data, docx_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 docx 헤더
        }
    } else if (strstr(path, ".doc") != NULL) {
        unsigned char doc_header[] = DOC_HEADER;
        if (memcmp(data, doc_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 doc 헤더
        }
    } else if (strstr(path, ".mp4") != NULL) {
        unsigned char mp4_header[] = MP4_HEADER;
        if (memcmp(data, mp4_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 mp4 헤더
        }
    } else if (strstr(path, ".zip") != NULL) {
        unsigned char zip_header[] = ZIP_HEADER;
        if (memcmp(data, zip_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 zip 헤더
        }
    } else if (strstr(path, ".sqlite") != NULL) {
        unsigned char sqlite_header[] = SQLITE_HEADER;
        if (memcmp(data, sqlite_header, HEADER_SIZE) != 0) {
            return 1;  // 잘못된 sqlite 헤더
        }
    } else {
        return 0;  // 헤더를 확인할 수 없는 확장자
    }
    return 0;  // 올바른 헤더
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
static int is_read_only(const char* path) {
    const char* ext = strrchr(path, '.');
    if (ext) {
        if (strcmp(ext, ".mp3") == 0 || strcmp(ext, ".pdf") == 0)
            return 1;  // 읽기 전용
    }
    return 0;  // 읽기/쓰기 가능
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

    // 미끼 파일 감지
    if (strcmp(path, honeypot_path) == 0) {
        terminate_ransomware_process(path); // 미끼 파일 접근 시 해당 프로세스 종료
    }

    int res = openat(base_fd, relpath, fi->flags);
    if (res == -1)
        return -errno;

    fi->fh = res;
    return 0;
}

static int myfs_read(const char *path, char *buf, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    // 미끼 파일 감지
    if (strcmp(path, honeypot_path) == 0) {
        terminate_ransomware_process(path); // 미끼 파일 접근 시 해당 프로세스 종료
    }

    int res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;

    return res;
}


static int myfs_write(const char *path, const char *buf, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    char relpath[PATH_MAX];
    get_relative_path(path, relpath);  // 상대 경로 생성

    unsigned char *data = (unsigned char *) buf;
    // 헤더 검사
    int header_check_result = check_header_for_extension(path, data);

    // 이전 엔트로피 가져오기
    double previous_entropy = get_previous_entropy(relpath);

    // 새 데이터의 엔트로피 계산
    double new_entropy = calculate_entropy(buf, size);

    double threshold = get_threshold_by_extension(path);
       
    // .mp3, .pdf 파일에 대한 쓰기 작업 차단
    if (is_read_only(relpath)) {
        // 로그 출력
        fprintf(stderr, "read only file!!\n");
        fflush(stderr);
        return -EACCES;
    }

    // 헤더 검사결과로 차단여부 결정
    if (header_check_result == 1) {
        // 로그 출력
        fprintf(stderr, "hedaer problem!!\n");
        fflush(stderr);
        return -EIO;
    }

    // 비정상적인 쓰기 작업 감지 (예: 크기나 빈도가 과도하게 많을 경우)
    if (detect_ransomware_activity(size)) {
        // 로그 출력
        fprintf(stderr, "ransomwar!!!\n");
        fflush(stderr);
        return -EIO;  // unnormal write deny
    }

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
static const struct fuse_operations fuse_oper = {
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

    // 미끼 파일 생성
    create_honeypot_file(mountpoint);

    // 기존 파일의 초기 엔트로피 기록
    initialize_entropy_log(mountpoint);

    free(mountpoint);

    // FUSE 실행
    int ret = fuse_main(args.argc, args.argv, &fuse_oper, NULL);

    // 자원 해제
    fuse_opt_free_args(&args);
    close(base_fd);

    return ret;
}