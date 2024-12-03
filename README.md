# 🛡️ fuse_file_system_ransomware_defender 🛡️
fuse filesystem을 이용하여 랜섬웨어 탐지하기

## 📋 Outline
- fuse file system 구축하고 해당 target directory를 mount

- target directory 내부에서 랜섬웨어 실행시켰을 때 적절한 대응을 수행

## ⚙️ Environment settings
☑️ OS  : `ububtu 22.04`

☑️ Language : `C`

☑️ compile 
```bash
gcc -Wall main.c `pkg-config fuse3 --cflags --libs` -lm -o fuse
```

☑️ mount
```bash
./fuse ./{TARGET_DIR}
```

☑️ unmount
```bash
fusermount3 -u ./{TARGET_DIR}
```

## 💡 Detection Logic
### 1️⃣ 일부 확장자 읽기 전용 확장자로 설정

- `.mp3`, `.pdf`파일

→ 위 사용자 .mp3와 .pdf에 대해 write작업을 하지않는 사용자임 

```c
#define READ_ONLY_EXTENSIONS ".mp3", ".pdf"
```

.mp3와 .pdf파일에 대해 write요청이 들어왔을 경우 에러 



### 2️⃣ 비정상적인 헤더 패턴 감지하기

- write 시 데이터 헤더 확인
- 특정 비트 패턴이 있는지 검사

```c
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

```

write작업시 헤더를 확인해 파일 확장자에 따른 정상적인 헤더인지 확인

다를시 에러



### 3️⃣ 비정상적인 쓰기 작업 감지

- 쓰고자 하는 데이터의 크기 & 빈도가 과도하게 많은 경우

```c
#define MAX_WRITE_SIZE 1048576 // 1MB
#define MAX_WRITE_COUNT 50
#define TIME_WINDOW 60
```



### 4️⃣ 상대적 엔트로피 차이로 감지

- low entropy값을 가지고 있는 txt 확장자와 같은 파일은
    - threshold 2.5로 설정
- high entropy값을 가지고 있는 jpg와 같은 확장자는
    - threshold 0.5로 설정

```c
const FileThreshold thresholds[] = {
    {".txt",  2.5}, {".docx", 1.5}, {".doc",  1.2}, {".dll",  0.5}, {".mp3",  0.5}, {".csv",  1.5},
    {".jpg",  0.5}, {".pptx", 1.5}, {".pdf",  1.0}, {".json", 1.0}, {".log",  1.2}, {".xlsx", 1.5},
    {".xls",  1.5}, {".exe",  0.5}, {".bmp",  0.5}, {".zip",  0.5}, {".svg",  1.0}, {".html", 1.5},
    {".c",    1.0}, {".cpp",  1.0}, {".py",   1.0}, {".tmp",  1.0}, {".hwp",  1.5}, {".hwpx", 1.5},
    {".db",   0.5}, {".ppt",  1.5}, {".old",  1.0}, {".png",  0.5}, {".mp4",  0.5}, {NULL,    1.0}
};
```

기존의 높은 엔트로피 값을 가지는 jpg와 pdf와 같은 확장자의 기본 엔트로피가 7.0~8.0정도로 측정됨

이는 암호화 파일의 엔트로피와 맞먹음

→ 절대적인 엔트로피 임계값을 설정하여 측정하기에는 한계가 있다고 판단.

⇒ 상대적인 엔트로피 변화량을 각각의 확장자마다 측정하여 큰 엔트로피의 변화가 있는 경우에 탐지하도록 로직을 구성

📢한계점: 

기존의 큰 엔트로피를 가지고 있는 경우 (ex 8.0의 엔트로피를 가지고 있는 pdf)에는 암호화 파일이 8.5 이상이어야지 탐지하는데 이는 현실적으로 쉽지 않음 → 큰 엔트로피를 가지고 있는 확장자에 대해서는 적용하기가 어려움



### 5️⃣ 미끼 파일 생성

- 동적으로 미끼 파일 생성
    - `"h_o_nne_y_p_o_t.txt"`
        - honney_pot.txt라고 네이밍하면 랜섬웨어 악성 프로그래밍이 탐지할 수 있으니까
        dirty하게 작성
    - 미끼파일을 읽거나 open하려는 경우 대상 프로세스를 강제 종료

```c
#define HONEYPOT_FILENAME "h_o_nne_y_p_o_t.txt"
#define HONEYPOT_CONTENT "This is a honeypot file. Do not access."
```

- 일반적인 client는 미끼 파일을 볼 수 없음
- 랜섬웨어 파일은 공격하고자하는 확장자는 전부 다 읽어들임 → 이를 이용하여 미끼파일을 txt 확장자로 설정하여 읽는 경우 랜섬웨어를 종료시키도록 구성함
