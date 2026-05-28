/* PS5 trophy unlocker — homebrew payload for jailbroken consoles.
 * Modifier le 12 mai 2026 Niko Bellik base partage par SonicISO
 *
 * Usage:
 *   nc <ps5> 9021 < trophy_unlocker.elf       launches the payload
 *   nc <ps5> 9022                              streams the debug log
 *
 * Logging:
 *   Every log() line is also appended to an in-memory ring buffer; a
 *   background thread listens on TCP 9022 and replays the buffer +
 *   streams new lines to any client that connects. So you can launch
 *   the payload, then open netcat on 9022 at any time to inspect what
 *   it did — even after main() has exited (we hold the listener thread
 *   alive for LOG_HOLD_MS milliseconds after main returns).
 *
 *   Toasts are still emitted for the major milestones so you can see
 *   high-level progress without netcat.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/proc.h>
#include <sys/user.h>
#include <sys/sysctl.h>

#ifndef PUBLIC_SILENT
#define PUBLIC_SILENT 0
#endif

#ifndef DISABLE_LOG_FILE
#define DISABLE_LOG_FILE 0
#endif

/* -------------------------------------------------------- PS5 libkernel */

typedef struct {
    char  pad1[45];
    char  message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);
int sceKernelUsleep(unsigned int usec);
int sceKernelSleep(unsigned int sec);

int sceKernelLoadStartModule(const char *path, size_t, const void *,
                             uint32_t, void *, int *);
int sceKernelStopUnloadModule(int, size_t, const void *, uint32_t, void *, int *);
int sceKernelDlsym(int handle, const char *name, void **addr);
int sceSysmoduleLoadModule(uint32_t id);
int sceSysmoduleLoadModuleInternal(uint32_t id);
int getpid(void);
int kernel_dynlib_handle(int pid, const char* basename, uint32_t *handle);
intptr_t kernel_dynlib_dlsym(int pid, uint32_t handle, const char *sym);
int kernel_mprotect(int pid, unsigned long addr, unsigned long size, int prot);

typedef struct app_info {
    uint32_t app_id;
    uint64_t unknown1;
    uint32_t app_type;
    char     title_id[10];
    char     unknown2[0x3c];
} app_info_t;

int sceKernelGetAppInfo(int pid, app_info_t *info);

/* sockets (FreeBSD-style; we link libkernel_web which re-exports them) */
int  close(int);
int  open(const char *, int, ...);
int  read(int, void *, size_t);
int  write(int, const void *, size_t);

#ifndef AF_INET
#define AF_INET            2
#endif
#ifndef SOCK_STREAM
#define SOCK_STREAM        1
#endif
#ifndef SOL_SOCKET
#define SOL_SOCKET     0xFFFF
#endif
#ifndef SO_REUSEADDR
#define SO_REUSEADDR    0x0004
#endif
#ifndef INADDR_ANY
#define INADDR_ANY     0x00000000
#endif

struct sockaddr_in {
    uint8_t  sin_len;
    uint8_t  sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    char     sin_zero[8];
};

/* pthread */
typedef void *ScePthread;
typedef void *ScePthreadAttr;
int scePthreadCreate(ScePthread *thread, const ScePthreadAttr *attr,
                     void *(*entry)(void *), void *arg, const char *name);
int scePthreadDetach(ScePthread thread);

/* htons */
static inline uint16_t htons16(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

/* -------------------------------------------------------- log subsystem */

#ifndef LOG_PORT
#define LOG_PORT       9022
#endif
#define LOG_BUFSZ      (64 * 1024)   /* 64 KiB ring */
#define LOG_HOLD_MS    (60 * 1000)   /* keep listener alive 60s post-main */
#define LOG_READY_WAIT_US (2 * 1000 * 1000)
#define LOG_FILE_PATH  "/data/trophy_unlocker_log.txt"

#define SCE_SYSMODULE_NP_UNIVERSAL_DATA_SYSTEM 0x0105
#define SCE_SYSMODULE_NP_TROPHY2               0x0110

#define O_RDONLY       0x0000
#define O_WRONLY       0x0001
#define O_APPEND       0x0008
#define O_CREAT        0x0200

#ifndef PROT_READ
#define PROT_READ      0x1
#endif
#ifndef PROT_WRITE
#define PROT_WRITE     0x2
#endif
#ifndef PROT_EXEC
#define PROT_EXEC      0x4
#endif

static char     log_buf[LOG_BUFSZ];
static size_t   log_head;    /* next write offset (linear; not wrapped) */
static int      log_clients[8];
static int      log_n_clients;
static int      log_listener_running;
static int      log_listener_failed;
static int      log_file_fd = -1;

static void
log_file_init(void)
{
    if (PUBLIC_SILENT || DISABLE_LOG_FILE)
        return;

    log_file_fd = open(LOG_FILE_PATH, O_WRONLY | O_CREAT | O_APPEND, 0666);
}

static void
log_append_raw(const char *s, size_t n)
{
    if (PUBLIC_SILENT) {
        (void)s;
        (void)n;
        return;
    }

    /* If buffer would overflow, drop the oldest half. */
    if (log_head + n > LOG_BUFSZ) {
        size_t keep = LOG_BUFSZ / 2;
        if (log_head > keep) {
            memmove(log_buf, log_buf + log_head - keep, keep);
            log_head = keep;
        } else {
            /* incoming line itself larger than buffer — clip */
            log_head = 0;
            if (n > LOG_BUFSZ) n = LOG_BUFSZ;
        }
    }
    memcpy(log_buf + log_head, s, n);
    log_head += n;

    if (log_file_fd >= 0)
        (void)write(log_file_fd, s, n);

    /* Push to any connected clients (best-effort, ignore errors). */
    for (int i = 0; i < log_n_clients; i++) {
        if (log_clients[i] >= 0) {
            if (send(log_clients[i], s, n, 0) < 0) {
                close(log_clients[i]);
                log_clients[i] = -1;
            }
        }
    }
}

static void
log_append_cstr(const char *s)
{
    log_append_raw(s, strlen(s));
}

static void
notify(const char *fmt, ...)
{
    char  line[1024];
    int   n;

    if (PUBLIC_SILENT) {
        (void)fmt;
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof line) n = sizeof line - 1;

    /* 1. Append to log buffer + push to TCP clients first. */
    log_append_raw(line, (size_t)n);
    log_append_raw("\n", 1);

    /* 2. Toast on the PS5 (one-line summary). */
    notify_request_t req;
    memset(&req, 0, sizeof req);
    memcpy(req.message, line, (size_t)n);
    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);

    /* 3. Give the toast daemon time to ingest before any subsequent
     *    rapid call (or before the kernel SIGKILLs us). */
    sceKernelUsleep(150000);
}

/* log() variant that DOESN'T toast — for verbose messages we want over
 * netcat but don't want spamming the PS5 notification panel. */
static void
logf(const char *fmt, ...)
{
    char line[1024];
    int  n;
    va_list ap;

    if (PUBLIC_SILENT) {
        (void)fmt;
        return;
    }

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof line) n = sizeof line - 1;
    log_append_raw(line, (size_t)n);
    log_append_raw("\n", 1);
}

static void *
log_listener_thread(void *arg)
{
    (void)arg;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        log_listener_failed = 1;
        return NULL;
    }

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_len    = sizeof sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons16(LOG_PORT);
    sa.sin_addr   = INADDR_ANY;

    if (bind(s, (const struct sockaddr *)&sa, sizeof sa) < 0) {
        log_listener_failed = 1;
        close(s);
        return NULL;
    }
    if (listen(s, 4) < 0) {
        log_listener_failed = 1;
        close(s);
        return NULL;
    }
    log_listener_running = 1;
#if LOG_PORT == 9021
    log_append_cstr("trophy_unlocker: TCP log listener ready on port 9021\n");
#elif LOG_PORT == 9022
    log_append_cstr("trophy_unlocker: TCP log listener ready on port 9022\n");
#else
    logf("trophy_unlocker: TCP log listener ready on port %d", LOG_PORT);
#endif

    for (;;) {
        struct sockaddr_in ca;
        socklen_t calen = sizeof ca;
        int c = accept(s, (struct sockaddr *)&ca, &calen);
        if (c < 0) {
            sceKernelUsleep(100000);
            continue;
        }
        /* Replay the buffer so a client that connects after the
         * interesting events still gets the history. */
        if (log_head > 0)
            (void)send(c, log_buf, log_head, 0);

        /* Park the fd so future log_append_raw() pushes to it too. */
        if (log_n_clients < (int)(sizeof log_clients / sizeof log_clients[0])) {
            log_clients[log_n_clients++] = c;
        } else {
            close(c);
        }
    }
    /* not reached */
}

static void
log_init(void)
{
    if (PUBLIC_SILENT)
        return;

    log_file_init();
    log_append_raw("\n--- trophy_unlocker log start ---\n", 34);

    for (int i = 0; i < (int)(sizeof log_clients / sizeof log_clients[0]); i++)
        log_clients[i] = -1;

    ScePthread th;
    int rc = scePthreadCreate(&th, NULL, log_listener_thread, NULL,
                              "trophy_log");
    if (rc == 0) {
        scePthreadDetach(th);
        for (int waited = 0;
             waited < LOG_READY_WAIT_US && !log_listener_running && !log_listener_failed;
             waited += 10000) {
            sceKernelUsleep(10000);
        }
        if (!log_listener_running) {
            log_append_cstr("trophy_unlocker: TCP log listener failed to start\n");
        }
    } else {
        log_append_cstr("trophy_unlocker: scePthreadCreate(log) failed\n");
    }
}

static void
log_drain(void)
{
    if (PUBLIC_SILENT)
        return;

    /* Hold the listener thread alive for LOG_HOLD_MS so the user can
     * still connect with netcat after main() has finished its work. */
    if (!log_listener_running) return;
    sceKernelUsleep(LOG_HOLD_MS * 1000);
}

/* ---------------------------------------------- trophy API (runtime dlsym) */

typedef struct {
    char     data[9];
    char     term;
    uint8_t  num;
    char     dummy;
} SceNpCommunicationId;

typedef struct {
    uint8_t  data[160];
} SceNpCommunicationSignature;

typedef struct {
    size_t   size;
    uint32_t numGroups;
    uint32_t numTrophies;
    uint32_t numPlatinum;
    uint32_t numGold;
    uint32_t numSilver;
    uint32_t numBronze;
    char     title[128];
    char     description[1024];
} SceNpTrophyGameDetails;

typedef int32_t SceUserServiceUserId;
typedef uint32_t SceNpServiceLabel;
typedef int32_t SceNpTrophy2Handle;
typedef int32_t SceNpTrophy2Context;
typedef int32_t SceNpTrophy2Id;
typedef int32_t SceNpTrophy2GroupId;
typedef int32_t SceNpTrophy2Grade;
typedef int32_t SceNpTrophy2ProgressType;
typedef void (*SceNpTrophy2UnlockCallback)(SceNpTrophy2Context,
                                           SceNpTrophy2Id,
                                           void *);
typedef int32_t SceNpUniversalDataSystemContext;
typedef int32_t SceNpUniversalDataSystemHandle;

typedef struct SceNpUniversalDataSystemEvent SceNpUniversalDataSystemEvent;
typedef struct SceNpUniversalDataSystemEventPropertyObject SceNpUniversalDataSystemEventPropertyObject;

typedef struct {
    size_t size;
    size_t poolSize;
} SceNpUniversalDataSystemInitParam;

typedef struct {
    uint32_t numGroups;
    uint32_t numTrophies;
    uint32_t numPlatinum;
    uint32_t numGold;
    uint32_t numSilver;
    uint32_t numBronze;
    char title[128];
} SceNpTrophy2GameDetails;

typedef struct {
    uint32_t unlockedTrophies;
    uint32_t unlockedPlatinum;
    uint32_t unlockedGold;
    uint32_t unlockedSilver;
    uint32_t unlockedBronze;
    uint32_t progressPercentage;
} SceNpTrophy2GameData;

typedef struct {
    uint64_t tick;
} SceRtcTick;

typedef struct {
    SceNpTrophy2ProgressType type;
    uint8_t reserved[4];
    union {
        uint64_t valueUInt64;
    } value;
} SceNpTrophy2Progress;

typedef struct {
    SceNpTrophy2Id trophyId;
    SceNpTrophy2Grade trophyGrade;
    SceNpTrophy2GroupId groupId;
    bool hidden;
    bool hasReward;
    uint8_t reserved2[2];
    SceNpTrophy2Progress target;
    char name[128];
    char description[1024];
    char reward[128];
} SceNpTrophy2Details;

typedef struct {
    SceNpTrophy2Id trophyId;
    bool unlocked;
    uint8_t reserved[3];
    SceNpTrophy2Progress progress;
    SceRtcTick timestamp;
} SceNpTrophy2Data;

#define SCE_NP_TROPHY_INVALID_TROPHY_ID             (-1)
#define SCE_NP_TROPHY_INVALID_HANDLE                (-1)
#define SCE_NP_TROPHY_INVALID_CONTEXT               (-1)
#define SCE_NP_TROPHY_ERROR_INVALID_CONTEXT         0x80551609
#define SCE_NP_TROPHY_ERROR_INVALID_TROPHY_ID       0x8055160A
#define SCE_NP_TROPHY_ERROR_TROPHY_ALREADY_UNLOCKED 0x8055160C
#define SCE_NP_TROPHY_ERROR_PLATINUM_CANNOT_UNLOCK 0x8055160D
#define SCE_NP_TROPHY_ERROR_ALREADY_REGISTERED      0x80551610
#define SCE_NP_TROPHY_ERROR_CONTEXT_ALREADY_EXISTS  0x80551613

#define SCE_USER_SERVICE_USER_ID_INVALID            (-1)
#define SCE_NP_TROPHY2_INVALID_HANDLE               (-1)
#define SCE_NP_TROPHY2_INVALID_CONTEXT              (-1)
#define SCE_NP_TROPHY2_INVALID_TROPHY_ID            (-1)
#define SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT (-1)
#define SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE  (-1)
#define SCE_NP_UNIVERSAL_DATA_SYSTEM_POST_EVENT_OPTION_GENERATED_BY_CODEGEN 1ULL
#define UDS_POOL_SIZE                               (16 * 1024)
#define DEFAULT_TROPHY_ID                           0
#define TROPHY_UNLOCKER_ID_FILE                     "/data/trophy_unlocker_id.txt"
#define TROPHY_UNLOCKER_CONFIG_FILE                 "/data/trophy_unlocker_config.txt"
#define TROPHY_UNLOCKER_NPCOMM_FILE                 "/data/trophy_unlocker_npcomm.txt"
#define TROPHY_UNLOCKER_NPSIG_FILE                  "/data/trophy_unlocker_npsig.bin"
#define TROPHY_UNLOCKER_COUNT_FILE                  "/data/trophy_unlocker_count.txt"
#define TROPHY_UNLOCKER_PLATFORM_FILE               "/data/trophy_unlocker_platform.txt"
#define TROPHY_UNLOCKER_MAX_ALL                     128
#define TROPHY_UNLOCKER_MAX_SIG_CANDIDATES          8
#define TROPHY_UCP_SCAN_BYTES                       (64 * 1024)
#define TROPHY_UCP_HEADER_SIZE                      0x60
#define TROPHY_UCP_DEFAULT_ENTRY_SIZE               0x40
#define UDS_ERROR_INVALID_ARGUMENT_RC               0x80553102U
#define UDS_ERROR_ALREADY_INITIALIZED_RC            0x80553118U
#define REGISTER_CONTEXT_REFUSED_RC                0x8094000fU
#define UDS_CONTEXT_SCAN_BASE                       0x00040000
#define UDS_CONTEXT_SCAN_LIMIT                      256
#define TROPHY2_CONTEXT_SCAN_BASE                   0x00040000
#define TROPHY2_CONTEXT_SCAN_LIMIT                  64
#define TROPHY2_LAST_SEEN_CONTEXT_FALLBACK          0x00040004
#define TROPHY1_CONTEXT_SCAN_BASE                   0x00040000
#define TROPHY1_CONTEXT_SCAN_LIMIT                  4096
#ifndef NP_SERVICE_LABEL_SCAN_MAX
#define NP_SERVICE_LABEL_SCAN_MAX                   0
#endif
#ifndef BUILD_TAG
#define BUILD_TAG                                   "V56 live range"
#endif
#ifndef ENABLE_HEAP_CONTEXT_SCAN
#define ENABLE_HEAP_CONTEXT_SCAN                    0
#endif
#ifndef ENABLE_TROPHY2_CANDIDATE_INFO_TEST
#define ENABLE_TROPHY2_CANDIDATE_INFO_TEST         0
#endif
#ifndef ENABLE_TROPHY2_CANDIDATE_HANDLE_TEST
#define ENABLE_TROPHY2_CANDIDATE_HANDLE_TEST       0
#endif
#ifndef ENABLE_REGISTER_PROBES
#define ENABLE_REGISTER_PROBES                      1
#endif
#ifndef ENABLE_UDS_CONTEXT_SCAN
#define ENABLE_UDS_CONTEXT_SCAN                     0
#endif
#ifndef ENABLE_TROPHY2_CONTEXT_SCAN
#define ENABLE_TROPHY2_CONTEXT_SCAN                 1
#endif
#ifndef ENABLE_REMOTE_VSH_SYMBOL_PROBE
#define ENABLE_REMOTE_VSH_SYMBOL_PROBE              0
#endif
#ifndef ENABLE_CALLBACK_MONITOR
#define ENABLE_CALLBACK_MONITOR                     0
#endif
#ifndef ENABLE_UDS_POSTEVENT_HOOK
#define ENABLE_UDS_POSTEVENT_HOOK                   0
#endif
#ifndef ENABLE_UDS_POSTEVENT_TRACE_ONLY
#define ENABLE_UDS_POSTEVENT_TRACE_ONLY             0
#endif
#ifndef ENABLE_UDS_LIVE_CONTEXT_FILE
#define ENABLE_UDS_LIVE_CONTEXT_FILE                0
#endif
#define UDS_LIVE_CONTEXT_FILE                       "/data/trophy_unlocker_ctx.txt"
#ifndef UDS_HOOK_MONITOR_SECONDS
#define UDS_HOOK_MONITOR_SECONDS                    90
#endif
#define UDS_HOOK_PAGE_SIZE                          0x4000
#define UDS_HOOK_PATCH_LEN                          17
#define UDS_TRACE_EVENT_SLOTS                       32
#define UDS_TRACE_NAME_MAX                          64
#define GOAT_TROPHY_MIN_ID                          0
#define GOAT_TROPHY_MAX_ID                          38
#define CALLBACK_MONITOR_SECONDS                    120
#define CALLBACK_MONITOR_STEP_USEC                  100000
#define ENABLE_THREADED_REGISTER_PROBE              0
#define TROPHY2_THREAD_WAIT_MS                      12000
#define TROPHY2_HEAP_SCAN_START                     0x00000008811d0000ULL
#define TROPHY2_HEAP_SCAN_SIZE                      0x000c0000ULL
#define UDS_HEAP_SCAN_START                         0x0000000881a30000ULL
#define UDS_HEAP_SCAN_SIZE                          0x00040000ULL
#define V31_CANDIDATE_MAX                           64
#define POST_UNLOCK_CALLBACK_PUMP_COUNT             8
#define POST_UNLOCK_FINAL_PUMP_COUNT                8
#define POST_UNLOCK_SETTLE_USEC                     1500000
#ifndef POST_UNLOCK_EVENT_DELAY_USEC
#define POST_UNLOCK_EVENT_DELAY_USEC                250000
#endif
#ifndef PS4_UNLOCK_EVENT_DELAY_USEC
#define PS4_UNLOCK_EVENT_DELAY_USEC                 0
#endif
#ifndef ENABLE_TROPHY2_POST_INFO_DIAG
#define ENABLE_TROPHY2_POST_INFO_DIAG               1
#endif
#ifndef ENABLE_EXISTING_UDS_CONTEXT_FULL_POST
#define ENABLE_EXISTING_UDS_CONTEXT_FULL_POST       0
#endif
#ifndef ENABLE_TROPHY2_SHOW_LIST_AFTER_POST
#define ENABLE_TROPHY2_SHOW_LIST_AFTER_POST         0
#endif
#ifndef ENABLE_TROPHY2_SHOW_LIST_IN_SCAN
#define ENABLE_TROPHY2_SHOW_LIST_IN_SCAN            0
#endif
#ifndef ENABLE_PS4_TROPHY1_MODE
#define ENABLE_PS4_TROPHY1_MODE                     0
#endif
#ifndef ENABLE_AUTO_PS4_PS5_MODE
#define ENABLE_AUTO_PS4_PS5_MODE                    0
#endif
#define TROPHY2_SCAN_TROPHY_INFO_LIMIT              64
#define FORCE_TROPHY_ID_FOR_DIAG                    -1

static int (*p_CreateContext) (int32_t *, SceUserServiceUserId,
                               SceNpServiceLabel, uint64_t);
static int (*p_DestroyContext)(int32_t);
static int (*p_CreateHandle)  (int32_t *);
static int (*p_DestroyHandle) (int32_t);
static int (*p_RegisterContext)(int32_t, int32_t, uint64_t);
static int (*p_GetGameInfo)   (int32_t, int32_t, SceNpTrophyGameDetails *, void *);
static int (*p_UnlockTrophy)  (int32_t, int32_t, int32_t, int32_t *);
static int (*p_GetRunning)    (int32_t, SceNpCommunicationId *);

static int (*p_UserServiceGetInitialUser)(SceUserServiceUserId *);

static int (*p_Trophy2CreateHandle)(SceNpTrophy2Handle *);
static int (*p_Trophy2DestroyHandle)(SceNpTrophy2Handle);
static int (*p_Trophy2CreateContext)(SceNpTrophy2Context *,
                                     SceUserServiceUserId,
                                     SceNpServiceLabel,
                                     uint64_t);
static int (*p_Trophy2DestroyContext)(SceNpTrophy2Context);
static int (*p_Trophy2RegisterContext)(SceNpTrophy2Context,
                                       SceNpTrophy2Handle,
                                       uint64_t);
static int (*p_Trophy2RegisterUnlockCallback)(SceNpTrophy2UnlockCallback,
                                              void *);
static int (*p_Trophy2UnregisterUnlockCallback)(void);
static int (*p_Trophy2GetGameInfo)(SceNpTrophy2Context,
                                   SceNpTrophy2Handle,
                                   SceNpTrophy2GameDetails *,
                                   SceNpTrophy2GameData *);
static int (*p_Trophy2GetTrophyInfo)(SceNpTrophy2Context,
                                     SceNpTrophy2Handle,
                                     SceNpTrophy2Id,
                                     SceNpTrophy2Details *,
                                     SceNpTrophy2Data *);
static int (*p_Trophy2ShowTrophyList)(SceNpTrophy2Context);
static int (*p_NpCheckCallback)(void);

static int (*p_UdsInitialize)(const SceNpUniversalDataSystemInitParam *);
static int (*p_UdsTerminate)(void);
static int (*p_UdsCreateContext)(SceNpUniversalDataSystemContext *,
                                 SceUserServiceUserId,
                                 SceNpServiceLabel,
                                 uint64_t);
static int (*p_UdsDestroyContext)(SceNpUniversalDataSystemContext);
static int (*p_UdsRegisterContext)(SceNpUniversalDataSystemContext,
                                   SceNpUniversalDataSystemHandle,
                                   uint64_t);
static int (*p_UdsCreateHandle)(SceNpUniversalDataSystemHandle *);
static int (*p_UdsDestroyHandle)(SceNpUniversalDataSystemHandle);
static int (*p_UdsCreateEvent)(const char *,
                               const SceNpUniversalDataSystemEventPropertyObject *,
                               SceNpUniversalDataSystemEvent **,
                               SceNpUniversalDataSystemEventPropertyObject **);
static int (*p_UdsDestroyEvent)(SceNpUniversalDataSystemEvent *);
static int (*p_UdsPostEvent)(SceNpUniversalDataSystemContext,
                             SceNpUniversalDataSystemHandle,
                             const SceNpUniversalDataSystemEvent *,
                             uint64_t);
static int (*p_UdsPropSetInt32)(SceNpUniversalDataSystemEventPropertyObject *,
                                const char *,
                                int32_t);

static int trophy_h = -1;
static uint32_t trophy_kh;
static int trophy_use_kernel_dynlib;
static volatile int g_trophy2_unlock_callbacks;
static volatile SceNpTrophy2Context g_last_trophy2_unlock_context =
    SCE_NP_TROPHY2_INVALID_CONTEXT;
static volatile SceNpTrophy2Id g_last_trophy2_unlock_id =
    SCE_NP_TROPHY2_INVALID_TROPHY_ID;
static volatile SceNpTrophy2Context g_found_trophy2_context =
    SCE_NP_TROPHY2_INVALID_CONTEXT;
static volatile uint32_t g_found_trophy2_num_trophies;
static volatile uint32_t g_found_trophy2_unlocked_trophies;
static volatile SceNpUniversalDataSystemContext g_last_accepted_uds_context =
    SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
static uint8_t g_seen_trophy_unlocked[TROPHY_UNLOCKER_MAX_ALL];
static uint8_t g_seen_trophy_valid[TROPHY_UNLOCKER_MAX_ALL];
static int g_trophy2_symbols_ok;
static int g_uds_symbols_ok;
static int g_uds_only_mode;
static SceUserServiceUserId g_initial_user_id =
    SCE_USER_SERVICE_USER_ID_INVALID;

static void
trophy2_unlock_callback(SceNpTrophy2Context context,
                        SceNpTrophy2Id trophy_id,
                        void *userdata)
{
    g_trophy2_unlock_callbacks++;
    g_last_trophy2_unlock_context = context;
    g_last_trophy2_unlock_id = trophy_id;
    logf("V26 Trophy2 unlock callback ctx=%d id=%d userdata=%p",
         context, trophy_id, userdata);
}

static void
pump_np_callbacks(const char *phase, int count)
{
    if (p_NpCheckCallback == NULL) {
        logf("V26 sceNpCheckCallback unavailable phase=%s", phase);
        return;
    }

    for (int i = 0; i < count; i++) {
        int rc = p_NpCheckCallback();
        logf("V26 sceNpCheckCallback phase=%s step=%d/%d -> 0x%08x",
             phase, i + 1, count, rc);
        if (rc < 0)
            break;
        sceKernelUsleep(50000);
    }
}

static int
monitor_trophy2_unlock_callbacks(int seconds)
{
    int steps = seconds * (1000000 / CALLBACK_MONITOR_STEP_USEC);
    int last_count = g_trophy2_unlock_callbacks;

    logf("V49 callback monitor start seconds=%d steps=%d cb_start=%d",
         seconds, steps, last_count);
    notify("trophy_unlocker: V49 monitor %ds", seconds);

    for (int i = 0; i < steps; i++) {
        int rc = 0;

        if (p_NpCheckCallback != NULL)
            rc = p_NpCheckCallback();

        if (g_trophy2_unlock_callbacks != last_count) {
            last_count = g_trophy2_unlock_callbacks;
            logf("V49 callback monitor HIT count=%d ctx=%d id=%d rc=0x%08x",
                 last_count, g_last_trophy2_unlock_context,
                 g_last_trophy2_unlock_id, rc);
            notify("trophy_unlocker: V49 cb id=%d ctx=%d",
                   g_last_trophy2_unlock_id, g_last_trophy2_unlock_context);
        }

        if ((i % 50) == 0) {
            logf("V49 callback monitor tick sec=%d/%d cb=%d rc=0x%08x ctx=%d id=%d",
                 (i * CALLBACK_MONITOR_STEP_USEC) / 1000000, seconds,
                 g_trophy2_unlock_callbacks, rc,
                 g_last_trophy2_unlock_context, g_last_trophy2_unlock_id);
        }

        sceKernelUsleep(CALLBACK_MONITOR_STEP_USEC);
    }

    logf("V49 callback monitor done cb_total=%d last_ctx=%d last_id=%d",
         g_trophy2_unlock_callbacks, g_last_trophy2_unlock_context,
         g_last_trophy2_unlock_id);
    notify("trophy_unlocker: V49 monitor fini cb=%d",
           g_trophy2_unlock_callbacks);

    return g_trophy2_unlock_callbacks;
}

static void
probe_file_path(const char *path, const char *tag)
{
    int fd = open(path, O_RDONLY, 0);
    logf("probe open(%s:%s) -> %d", tag, path, fd);
    notify("DEBUG V13: probe %s fd=%d", tag, fd);
    if (fd >= 0)
        close(fd);
}

static void
probe_app0_trophy_package_files(void)
{
    static const struct { const char *path; const char *tag; } paths[] = {
        { "/app0/sce_sys/param.json",            "app0_param_json" },
        { "/app0/sce_sys/nptitle.dat",           "app0_nptitle" },
        { "/app0/sce_sys/trophy2/npbind.dat",    "app0_trophy2_npbind" },
        { "/app0/sce_sys/trophy2/trophy00.ucp",  "app0_trophy2_ucp" },
        { "/app0/sce_sys/uds/npbind.dat",        "app0_uds_npbind" },
        { "/app0/sce_sys/uds/uds00.ucp",         "app0_uds_ucp" },
        { NULL, NULL }
    };

    logf("V35 package file probe start");
    for (int i = 0; paths[i].path != NULL; i++)
        probe_file_path(paths[i].path, paths[i].tag);
    logf("V35 package file probe done");
}

static uint8_t g_ucp_scan_buf[TROPHY_UCP_SCAN_BYTES];

static uint32_t
read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int
parse_trop_png_name(const char *name, int *id_out)
{
    int id = 0;

    if (strncmp(name, "trop", 4) != 0)
        return -1;

    for (int i = 4; i < 8; i++) {
        if (name[i] < '0' || name[i] > '9')
            return -1;
        id = (id * 10) + (name[i] - '0');
    }

    if (name[8] != '.' || name[9] != 'p' ||
        name[10] != 'n' || name[11] != 'g')
        return -1;

    *id_out = id;
    return 0;
}

static int
copy_clean_ascii(char *dst, size_t dstsz, const char *src, size_t srcsz)
{
    size_t n = 0;

    if (dstsz == 0)
        return -1;

    while (n < srcsz && src[n] != '\0' &&
           src[n] != ' ' && src[n] != '\t' &&
           src[n] != '\r' && src[n] != '\n') {
        if (n + 1 >= dstsz)
            break;
        dst[n] = src[n];
        n++;
    }

    dst[n] = '\0';
    return n > 0 ? 0 : -1;
}

static int
get_current_app_title_token(char *title, size_t title_sz)
{
    app_info_t appinfo;
    int rc;

    memset(&appinfo, 0, sizeof appinfo);
    rc = sceKernelGetAppInfo(getpid(), &appinfo);
    if (rc != 0) {
        logf("V70 appinfo current pid=%d -> 0x%08x", getpid(), rc);
        return -1;
    }

    if (copy_clean_ascii(title, title_sz, appinfo.title_id,
                         sizeof appinfo.title_id) != 0) {
        logf("V70 appinfo current title empty appid=0x%08x", appinfo.app_id);
        return -1;
    }

    logf("V70 appinfo current appid=0x%08x title_token=%s",
         appinfo.app_id, title);
    return 0;
}

static int
is_npwr_at(const uint8_t *p)
{
    if (p[0] != 'N' || p[1] != 'P' || p[2] != 'W' || p[3] != 'R')
        return 0;

    for (int i = 4; i < 9; i++) {
        if (p[i] < '0' || p[i] > '9')
            return 0;
    }

    return p[9] == '_' && p[10] >= '0' && p[10] <= '9' &&
           p[11] >= '0' && p[11] <= '9';
}

static int
detect_npcomm_from_npbind_path(const char *path, char *npcomm, size_t npcomm_sz)
{
    int fd;
    int n;

    if (npcomm_sz < 13)
        return -1;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        logf("V70 npbind open(%s) -> %d", path, fd);
        return -1;
    }

    n = read(fd, g_ucp_scan_buf, sizeof g_ucp_scan_buf);
    close(fd);
    logf("V70 npbind read(%s) -> %d", path, n);
    if (n < 12)
        return -1;

    for (int i = 0; i + 12 <= n; i++) {
        if (!is_npwr_at(&g_ucp_scan_buf[i]))
            continue;

        memcpy(npcomm, &g_ucp_scan_buf[i], 12);
        npcomm[12] = '\0';
        logf("V70 npbind selected %s -> %s", path, npcomm);
        return 0;
    }

    logf("V70 npbind no NPWR in %s", path);
    return -1;
}

static int
detect_npcomm_from_override_file(char *npcomm, size_t npcomm_sz)
{
    int fd;
    int n;

    if (npcomm_sz < 13)
        return -1;

    fd = open(TROPHY_UNLOCKER_NPCOMM_FILE, O_RDONLY, 0);
    if (fd < 0) {
        logf("V71 npcomm override open(%s) -> %d",
             TROPHY_UNLOCKER_NPCOMM_FILE, fd);
        return -1;
    }

    n = read(fd, g_ucp_scan_buf, sizeof g_ucp_scan_buf);
    close(fd);
    logf("V71 npcomm override read(%s) -> %d",
         TROPHY_UNLOCKER_NPCOMM_FILE, n);
    if (n < 12)
        return -1;

    for (int i = 0; i + 12 <= n; i++) {
        if (!is_npwr_at(&g_ucp_scan_buf[i]))
            continue;

        memcpy(npcomm, &g_ucp_scan_buf[i], 12);
        npcomm[12] = '\0';
        logf("V71 npcomm override selected -> %s", npcomm);
        return 0;
    }

    logf("V71 npcomm override has no NPWR");
    return -1;
}

static int
try_npbind_candidate(const char *np_title_id, char *npcomm, size_t npcomm_sz)
{
    char path[192];

    if (np_title_id == NULL || np_title_id[0] == '\0')
        return -1;

    snprintf(path, sizeof path,
             "/system_data/priv/appmeta/%s/npbind.dat",
             np_title_id);
    if (detect_npcomm_from_npbind_path(path, npcomm, npcomm_sz) == 0)
        return 0;

    snprintf(path, sizeof path,
             "/system_data/priv/appmeta/%s/trophy2/npbind.dat",
             np_title_id);
    if (detect_npcomm_from_npbind_path(path, npcomm, npcomm_sz) == 0)
        return 0;

    snprintf(path, sizeof path,
             "/system_data/priv/appmeta/%s/trophy/npbind.dat",
             np_title_id);
    if (detect_npcomm_from_npbind_path(path, npcomm, npcomm_sz) == 0)
        return 0;

    snprintf(path, sizeof path,
             "/system_data/priv/appmeta/%s/uds/npbind.dat",
             np_title_id);
    return detect_npcomm_from_npbind_path(path, npcomm, npcomm_sz);
}

static int
detect_npcomm_for_current_app(char *npcomm, size_t npcomm_sz)
{
    char token[16];
    char np_title_id[16];

    if (detect_npcomm_from_npbind_path("/app0/sce_sys/trophy2/npbind.dat",
                                       npcomm, npcomm_sz) == 0)
        return 0;
    if (detect_npcomm_from_npbind_path("/app0/sce_sys/trophy/npbind.dat",
                                       npcomm, npcomm_sz) == 0)
        return 0;
    if (detect_npcomm_from_npbind_path("/app0/sce_sys/uds/npbind.dat",
                                       npcomm, npcomm_sz) == 0)
        return 0;
    if (detect_npcomm_from_override_file(npcomm, npcomm_sz) == 0)
        return 0;

    if (get_current_app_title_token(token, sizeof token) != 0)
        return -1;

    if (strncmp(token, "PPSA", 4) == 0 ||
        strncmp(token, "CUSA", 4) == 0) {
        if (try_npbind_candidate(token, npcomm, npcomm_sz) == 0)
            return 0;
    }

    snprintf(np_title_id, sizeof np_title_id, "PPSA%s", token);
    if (try_npbind_candidate(np_title_id, npcomm, npcomm_sz) == 0)
        return 0;

    snprintf(np_title_id, sizeof np_title_id, "CUSA%s", token);
    if (try_npbind_candidate(np_title_id, npcomm, npcomm_sz) == 0)
        return 0;

    logf("V70 current app NPWR not found token=%s", token);
    return -1;
}

static uint32_t
detect_trophy_count_from_trptitle_path(const char *path)
{
    int fd;
    int n;
    uint32_t count_a;
    uint32_t count_b;
    uint32_t selected;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        logf("V70 TRPTITLE open(%s) -> %d", path, fd);
        return 0;
    }

    n = read(fd, g_ucp_scan_buf, sizeof g_ucp_scan_buf);
    close(fd);
    logf("V70 TRPTITLE read(%s) -> %d", path, n);

    if (n < 0x180 ||
        memcmp(&g_ucp_scan_buf[0x00], "T2PD", 4) != 0 ||
        memcmp(&g_ucp_scan_buf[0x40], "T2TD", 4) != 0) {
        logf("V70 TRPTITLE invalid header path=%s", path);
        return 0;
    }

    count_a = read_be32(&g_ucp_scan_buf[0x11c]);
    count_b = read_be32(&g_ucp_scan_buf[0x17c]);
    logf("V70 TRPTITLE counts path=%s off11c=%u off17c=%u",
         path, count_a, count_b);

    selected = count_a;
    if (selected == 0 || selected > TROPHY_UNLOCKER_MAX_ALL)
        selected = count_b;
    if (selected == 0 || selected > TROPHY_UNLOCKER_MAX_ALL)
        return 0;

    return selected;
}

static uint32_t
detect_trophy_count_from_override_file(void)
{
    char text[32];
    const char *p;
    long value;
    int fd;
    int n;

    fd = open(TROPHY_UNLOCKER_COUNT_FILE, O_RDONLY, 0);
    if (fd < 0) {
        logf("V72 count override open(%s) -> %d",
             TROPHY_UNLOCKER_COUNT_FILE, fd);
        return 0;
    }

    n = read(fd, text, sizeof text - 1);
    close(fd);
    logf("V72 count override read(%s) -> %d",
         TROPHY_UNLOCKER_COUNT_FILE, n);
    if (n <= 0)
        return 0;

    text[n] = '\0';
    p = text;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;

    value = strtol(p, NULL, 10);
    if (value <= 0 || value > TROPHY_UNLOCKER_MAX_ALL) {
        logf("V72 count override invalid text='%s' value=%ld", text, value);
        return 0;
    }

    notify("trophy_unlocker: V72 count override trophies=%ld", value);
    logf("V72 count override selected -> %ld", value);
    return (uint32_t)value;
}

static uint32_t
detect_user_trptitle_trophy_count(void)
{
    char npcomm[13];
    char path[192];
    uint32_t count;

    if (g_initial_user_id == SCE_USER_SERVICE_USER_ID_INVALID) {
        logf("V70 user TRPTITLE skip: initial user unknown");
        return 0;
    }

    if (detect_npcomm_for_current_app(npcomm, sizeof npcomm) != 0) {
        logf("V70 user TRPTITLE skip: NPWR unknown");
        return 0;
    }

    snprintf(path, sizeof path,
             "/user/home/%08x/trophy2/nobackup/data/%s/TRPTITLE.DAT",
             (uint32_t)g_initial_user_id, npcomm);
    count = detect_trophy_count_from_trptitle_path(path);
    if (count > 0) {
        notify("trophy_unlocker: V70 TRPTITLE %s trophies=%u",
               npcomm, count);
        logf("V70 user TRPTITLE selected user=%08x npcomm=%s count=%u",
             (uint32_t)g_initial_user_id, npcomm, count);
    }

    return count;
}

static int
scan_trop_png_names_raw(const uint8_t *buf, int n, int *seen_out)
{
    int max_id = -1;
    int seen = 0;

    for (int i = 0; i + 12 <= n; i++) {
        int id;

        if (parse_trop_png_name((const char *)&buf[i], &id) != 0)
            continue;

        seen++;
        if (id > max_id)
            max_id = id;
    }

    *seen_out = seen;
    return max_id;
}

static uint32_t
detect_trophy_count_from_ucp_path(const char *path)
{
    int fd;
    int n;
    uint32_t file_count;
    uint32_t entry_size;
    int max_id = -1;
    int seen = 0;
    uint32_t trophies;

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        logf("V68 auto count open(%s) -> %d", path, fd);
        return 0;
    }

    n = read(fd, g_ucp_scan_buf, sizeof g_ucp_scan_buf);
    close(fd);
    logf("V68 auto count read(%s) -> %d", path, n);
    if (n < TROPHY_UCP_HEADER_SIZE)
        return 0;

    file_count = read_be32(&g_ucp_scan_buf[0x10]);
    entry_size = read_be32(&g_ucp_scan_buf[0x14]);
    logf("V68 auto count header files=%u entry=0x%04x",
         file_count, entry_size);

    if (file_count > 0 && file_count < 4096 &&
        entry_size >= 0x20 && entry_size <= 0x100) {
        uint64_t table_end =
            (uint64_t)TROPHY_UCP_HEADER_SIZE +
            ((uint64_t)file_count * (uint64_t)entry_size);

        if (table_end > (uint64_t)n)
            table_end = (uint64_t)n;

        for (uint64_t off = TROPHY_UCP_HEADER_SIZE;
             off + 12 <= table_end;
             off += entry_size) {
            int id;

            if (parse_trop_png_name((const char *)&g_ucp_scan_buf[off],
                                    &id) != 0)
                continue;

            seen++;
            if (id > max_id)
                max_id = id;
        }
    }

    if (max_id < 0) {
        max_id = scan_trop_png_names_raw(g_ucp_scan_buf, n, &seen);
        logf("V68 auto count raw scan seen=%d max_id=%d", seen, max_id);
    } else {
        logf("V68 auto count table scan seen=%d max_id=%d", seen, max_id);
    }

    if (max_id < 0)
        return 0;

    trophies = (uint32_t)max_id + 1;
    if (trophies > TROPHY_UNLOCKER_MAX_ALL) {
        logf("V68 auto count cap %u -> %u", trophies,
             (uint32_t)TROPHY_UNLOCKER_MAX_ALL);
        trophies = TROPHY_UNLOCKER_MAX_ALL;
    }

    return trophies;
}

static uint32_t
detect_app0_trophy_count_from_package(void)
{
    static const char *paths[] = {
        "/app0/sce_sys/trophy2/trophy00.ucp",
        "/app0/sce_sys/trophy/trophy00.ucp",
        "/app0/sce_sys/trophy/trophy00.trp",
        NULL
    };

    for (int i = 0; paths[i] != NULL; i++) {
        uint32_t count = detect_trophy_count_from_ucp_path(paths[i]);

        if (count > 0) {
            notify("trophy_unlocker: V68 auto trophies=%u", count);
            logf("V68 auto count selected %s -> %u", paths[i], count);
            return count;
        }
    }

    logf("V68 auto count failed for app0 trophy package");
    return 0;
}

static uint32_t
ensure_trophy_count(uint32_t num_trophies, const char *phase)
{
    uint32_t detected;

    if (num_trophies > 0)
        return num_trophies;

    detected = detect_app0_trophy_count_from_package();
    if (detected == 0)
        detected = detect_trophy_count_from_override_file();
    if (detected == 0)
        detected = detect_user_trptitle_trophy_count();
    if (detected == 0)
        notify("trophy_unlocker: V70 compteur trophees introuvable");

    logf("V68 ensure count phase=%s input=%u detected=%u",
         phase, num_trophies, detected);
    return detected;
}

static int
resolve_trophy_symbol(const char *name, void **slot)
{
    if (trophy_use_kernel_dynlib) {
        intptr_t addr = kernel_dynlib_dlsym(getpid(), trophy_kh, name);
        *slot = (void *)addr;
        return addr ? 0 : -1;
    }
    return sceKernelDlsym(trophy_h, name, slot);
}

static int __attribute__((unused))
scan_trophy_modules_in_processes(void)
{
    static const char *mods[] = {
        "libSceNpTrophy.sprx",
        "libSceNpTrophy2.sprx",
        "libSceNpTrophyCore.sprx",
        NULL
    };
    int hits = 0;

    notify("DEBUG V15: scanning pids for trophy libs");
    for (int pid = 1; pid < 2048; pid++) {
        for (int i = 0; mods[i]; i++) {
            uint32_t h = 0;
            int r = kernel_dynlib_handle(pid, mods[i], &h);
            if (r == 0 && h != 0) {
                hits++;
                logf("PIDSCAN hit pid=%d module=%s handle=0x%08x", pid, mods[i], h);
                notify("DEBUG V15: hit pid=%d %.24s h=0x%08x", pid, mods[i], h);
            }
        }
    }
    notify("DEBUG V15: pid scan done hits=%d", hits);
    return hits;
}

static void
log_process_info_for_pid(int target_pid)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0 };
    size_t buf_size = 0;
    void *buf = NULL;
    int found = 0;

    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0) {
        logf("V21 proc pid=%d sysctl(size) failed", target_pid);
        notify("DEBUG V21: proc pid=%d size failed", target_pid);
        return;
    }

    buf = malloc(buf_size);
    if (buf == NULL) {
        logf("V21 proc pid=%d malloc(%zu) failed", target_pid, buf_size);
        notify("DEBUG V21: proc pid=%d malloc failed", target_pid);
        return;
    }

    if (sysctl(mib, 4, buf, &buf_size, NULL, 0) != 0) {
        logf("V21 proc pid=%d sysctl(data) failed", target_pid);
        notify("DEBUG V21: proc pid=%d data failed", target_pid);
        free(buf);
        return;
    }

    for (char *ptr = (char *)buf; ptr < (char *)buf + buf_size;) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
        app_info_t appinfo;
        char title_id[11];

        if (ki->ki_structsize <= 0)
            break;

        if (ki->ki_pid == target_pid) {
            memset(&appinfo, 0, sizeof appinfo);
            if (sceKernelGetAppInfo(ki->ki_pid, &appinfo) != 0)
                memset(&appinfo, 0, sizeof appinfo);

            memcpy(title_id, appinfo.title_id, 10);
            title_id[10] = '\0';

            logf("V21 proc pid=%d ppid=%d pgid=%d sid=%d uid=%d appid=0x%04x title=%.10s comm=%s",
                 ki->ki_pid, ki->ki_ppid, ki->ki_pgid, ki->ki_sid,
                 ki->ki_uid, appinfo.app_id, title_id, ki->ki_comm);
            notify("DEBUG V21: proc pid=%d comm=%.32s title=%.10s",
                   ki->ki_pid, ki->ki_comm, title_id);
            found = 1;
            break;
        }

        ptr += ki->ki_structsize;
    }

    if (!found)
        notify("DEBUG V21: proc pid=%d not found", target_pid);

    free(buf);
}

static uint32_t
probe_dynlib_handle_for_pid(int pid, const char *module, const char *tag)
{
    uint32_t h = 0;
    int r = kernel_dynlib_handle(pid, module, &h);
    logf("V21 dynlib pid=%d tag=%s module=%s -> 0x%08x handle=0x%08x",
         pid, tag, module, r, h);
    notify("DEBUG V21: pid=%d %s rc=0x%08x h=0x%08x", pid, tag, r, h);
    return (r == 0) ? h : 0;
}

static void
probe_symbol_for_pid(int pid, uint32_t h, const char *tag, const char *sym)
{
    intptr_t addr = kernel_dynlib_dlsym(pid, h, sym);
    logf("V21 dlsym pid=%d tag=%s sym=%s -> %p", pid, tag, sym, (void *)addr);
}

static void
probe_symbol_list_for_pid(int pid, const char *module, const char *tag,
                          const char *const *symbols)
{
    uint32_t h = 0;
    int rc = kernel_dynlib_handle(pid, module, &h);

    logf("V54 remote dlsym pid=%d tag=%s module=%s handle_rc=0x%08x h=0x%08x",
         pid, tag, module, rc, h);
    if (rc != 0 || h == 0)
        return;

    for (int i = 0; symbols[i] != NULL; i++) {
        intptr_t addr = kernel_dynlib_dlsym(pid, h, symbols[i]);
        logf("V54 remote dlsym pid=%d tag=%s module=%s sym=%s -> %p",
             pid, tag, module, symbols[i], (void *)addr);
    }
}

static void
probe_vsh_system_symbols_for_pid(int pid)
{
    static const char *const trophy2_system_symbols[] = {
        "sceNpTrophy2SystemCreateHandle",
        "sceNpTrophy2SystemDestroyHandle",
        "sceNpTrophy2SystemCreateContext",
        "sceNpTrophy2SystemDestroyContext",
        "sceNpTrophy2SystemGetTrophyTitleData",
        "sceNpTrophy2SystemGetTrophyData",
        "sceNpTrophy2SystemListPlayedTitles",
        "sceNpTrophy2SystemGetTrophyTitleIdsByNpTitleId",
        "sceNpTrophy2SystemDebugUnlockTrophy",
        "sceNpTrophy2SystemDebugLockTrophy",
        "sceNpTrophy2SystemCheckNetSyncTitles",
        "sceNpTrophy2SystemNetSyncTitles",
        "sceNpTrophy2SystemIsServerAvailable",
        NULL
    };
    static const char *const uds_system_symbols[] = {
        "sceNpUniversalDataSystemIntCreateHandle",
        "sceNpUniversalDataSystemIntDestroyHandle",
        "sceNpUniversalDataSystemIntCreateContext",
        "sceNpUniversalDataSystemIntDestroyContext",
        "sceNpUniversalDataSystemVshPromoteCreateHandle",
        "sceNpUniversalDataSystemVshPromoteCheckRecoveryRequired2",
        "sceNpUniversalDataSystemVshPromoteRecovery2",
        NULL
    };
    static const char *const promote_symbols[] = {
        "sceNpTrophyVshPromote",
        "sceNpTrophy2VshPromote",
        "sceNpTrophy2VshPromoteCreateHandle",
        "sceNpTrophy2VshPromoteCheckRecoveryRequired",
        "sceNpTrophy2VshPromoteRecovery",
        "sceNpTrophy2VshPromoteCheckRecoveryRequired2",
        "sceNpTrophy2VshPromoteRecovery2",
        NULL
    };

    logf("V54 remote VSH symbol probe start pid=%d", pid);
    probe_symbol_list_for_pid(pid, "Sce.Vsh.Np.Trophy2.dll.sprx",
                              "vsh-trophy2", trophy2_system_symbols);
    probe_symbol_list_for_pid(pid, "Sce.Vsh.Np.TrophyAccessor.dll.sprx",
                              "vsh-accessor", trophy2_system_symbols);
    probe_symbol_list_for_pid(pid, "ReactNative.Modules.Vsh.Trophy.dll.sprx",
                              "rn-trophy", trophy2_system_symbols);
    probe_symbol_list_for_pid(pid, "Sce.Vsh.Np.Uds.dll.sprx",
                              "vsh-uds", uds_system_symbols);
    probe_symbol_list_for_pid(pid, "SceShellCore.elf",
                              "shell-promote", promote_symbols);
    logf("V54 remote VSH symbol probe done pid=%d", pid);
}

static void
probe_trophy_dynlibs_for_pid(int pid, const char *phase)
{
    uint32_t trophy1;
    uint32_t trophy2;
    uint32_t uds;

    logf("V21 probe_trophy_dynlibs phase=%s pid=%d", phase, pid);
    notify("DEBUG V21: probe %s pid=%d", phase, pid);

    trophy1 = probe_dynlib_handle_for_pid(pid, "libSceNpTrophy.sprx", "Trophy1");
    trophy2 = probe_dynlib_handle_for_pid(pid, "libSceNpTrophy2.sprx", "Trophy2");
    uds = probe_dynlib_handle_for_pid(pid, "libSceNpUniversalDataSystem.sprx", "UDS");

    if (trophy2 != 0) {
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2CreateContext");
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2CreateHandle");
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2RegisterContext");
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2GetGameInfo");
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2GetTrophyInfo");
        probe_symbol_for_pid(pid, trophy2, "Trophy2", "sceNpTrophy2ShowTrophyList");
        notify("DEBUG V21: Trophy2 symbols probed pid=%d", pid);
    }

    if (uds != 0) {
        probe_symbol_for_pid(pid, uds, "UDS", "sceNpUniversalDataSystemInitialize");
        probe_symbol_for_pid(pid, uds, "UDS", "sceNpUniversalDataSystemCreateEvent");
        probe_symbol_for_pid(pid, uds, "UDS", "sceNpUniversalDataSystemPostEvent");
        probe_symbol_for_pid(pid, uds, "UDS", "sceNpUniversalDataSystemEventPropertyObjectSetInt32");
        notify("DEBUG V21: UDS symbols probed pid=%d", pid);
    }

    (void)trophy1;
}

static void
probe_shellcore_trophy_path(const char *path, const char *tag)
{
    int fd = open(path, O_RDONLY, 0);
    logf("V33 path %s open(%s) -> %d", tag, path, fd);
    if (fd >= 0)
        close(fd);
}

static void
probe_shellcore_dynlib_symbol(const char *module, const char *sym)
{
    uint32_t h = 0;
    int rc = kernel_dynlib_handle(getpid(), module, &h);
    intptr_t addr = 0;

    if (rc == 0 && h != 0)
        addr = kernel_dynlib_dlsym(getpid(), h, sym);

    logf("V33 self dlsym module=%s handle_rc=0x%08x h=0x%08x sym=%s -> %p",
         module, rc, h, sym, (void *)addr);
}

static void
probe_shellcore_symbol_list(const char *module, const char *const *symbols)
{
    for (int i = 0; symbols[i] != NULL; i++)
        probe_shellcore_dynlib_symbol(module, symbols[i]);
}

static void
run_shellcore_trophy_service_diag(void)
{
    int self_pid = getpid();

    static const char *const trophy2_system_symbols[] = {
        "sceNpTrophy2SystemCreateHandle",
        "sceNpTrophy2SystemDestroyHandle",
        "sceNpTrophy2SystemAbortHandle",
        "sceNpTrophy2SystemCreateContext",
        "sceNpTrophy2SystemDestroyContext",
        "sceNpTrophy2SystemCheckCallback",
        "sceNpTrophy2SystemGetTrophyTitleData",
        "sceNpTrophy2SystemGetTrophyTitleDataByContext",
        "sceNpTrophy2SystemGetTrophyGroupData",
        "sceNpTrophy2SystemGetTrophyData",
        "sceNpTrophy2SystemGetTrophyTitleConf",
        "sceNpTrophy2SystemGetTrophyGroupConf",
        "sceNpTrophy2SystemGetTrophyConf",
        "sceNpTrophy2SystemGetTrophyTitleDetails",
        "sceNpTrophy2SystemGetTrophyGroupDetails",
        "sceNpTrophy2SystemGetTrophyDetails",
        "sceNpTrophy2SystemGetTrophySetArray",
        "sceNpTrophy2SystemListPlayedTitles",
        "sceNpTrophy2SystemListAllTitles",
        "sceNpTrophy2SystemGetTrophyTitleIdsByNpTitleId",
        "sceNpTrophy2SystemRemoveTitleData",
        "sceNpTrophy2SystemRemoveUserData",
        "sceNpTrophy2SystemRemoveUserDataWithServerData",
        "sceNpTrophy2SystemRemoveAll",
        "sceNpTrophy2SystemDebugUnlockTrophy",
        "sceNpTrophy2SystemDebugLockTrophy",
        "sceNpTrophy2SystemCheckNetSyncTitles",
        "sceNpTrophy2SystemNetSyncTitles",
        "sceNpTrophy2SystemIsServerAvailable",
        "sceNpTrophy2SystemRegisterTitleUpdateCallback",
        "sceNpTrophy2SystemUnregisterTitleUpdateCallback",
        "sceNpTrophy2SystemBuildTitleIconUri",
        "sceNpTrophy2SystemBuildGroupIconUri",
        "sceNpTrophy2SystemBuildTrophyIconUri",
        "sceNpTrophy2SystemBuildRewardIconUri",
        "sceNpTrophy2SystemBuildBgImageIconUri",
        "sceNpTrophy2SystemGetTrpIconByUri",
        NULL
    };

    static const char *const uds_system_symbols[] = {
        "sceNpUniversalDataSystemIntCreateHandle",
        "sceNpUniversalDataSystemIntDestroyHandle",
        "sceNpUniversalDataSystemIntAbortHandle",
        "sceNpUniversalDataSystemIntCreateContext",
        "sceNpUniversalDataSystemIntDestroyContext",
        "sceNpUniversalDataSystemIntCheckNetSyncTitles",
        "sceNpUniversalDataSystemIntNetSyncTitles",
        "sceNpUniversalDataSystemVshPromoteCheckRecoveryRequired2",
        "sceNpUniversalDataSystemVshPromoteRecovery2",
        "sceNpUniversalDataSystemVshPromoteCreateHandle",
        NULL
    };

    static const char *const trophy_vsh_promote_symbols[] = {
        "sceNpTrophyVshPromote",
        "sceNpTrophy2VshPromote",
        "sceNpTrophy2VshPromoteCreateHandle",
        "sceNpTrophy2VshPromoteCheckRecoveryRequired",
        "sceNpTrophy2VshPromoteRecovery",
        "sceNpTrophy2VshPromoteCheckRecoveryRequired2",
        "sceNpTrophy2VshPromoteRecovery2",
        NULL
    };

    notify("trophy_unlocker: V33 Shell diag pid=%d", self_pid);
    logf("V33 Shell diagnostic start pid=%d", self_pid);

    log_process_info_for_pid(self_pid);
    log_process_info_for_pid(56);
    log_process_info_for_pid(57);

    probe_trophy_dynlibs_for_pid(self_pid, "v33-shellcore-self");
    probe_trophy_dynlibs_for_pid(56, "v33-shellcore-pid56");
    probe_trophy_dynlibs_for_pid(57, "v33-shellcore-pid57");

    probe_shellcore_dynlib_symbol("libSceNpTrophy.sprx",
                                  "sceNpTrophyCreateContext");
    probe_shellcore_dynlib_symbol("libSceNpTrophy.sprx",
                                  "sceNpTrophyRegisterContext");
    probe_shellcore_dynlib_symbol("libSceNpTrophy.sprx",
                                  "sceNpTrophyUnlockTrophy");
    probe_shellcore_dynlib_symbol("libSceNpTrophy.sprx",
                                  "sceNpTrophyGetGameInfo");

    probe_shellcore_dynlib_symbol("libSceNpTrophy2.sprx",
                                  "sceNpTrophy2RegisterContext");
    probe_shellcore_dynlib_symbol("libSceNpTrophy2.sprx",
                                  "sceNpTrophy2GetTrophyInfo");
    probe_shellcore_dynlib_symbol("libSceNpTrophy2.sprx",
                                  "sceNpTrophy2ShowTrophyList");
    probe_shellcore_dynlib_symbol("libSceNpUniversalDataSystem.sprx",
                                  "sceNpUniversalDataSystemPostEvent");

    logf("V52 probing Sce.Vsh.Np.Trophy2 system symbols");
    probe_shellcore_symbol_list("Sce.Vsh.Np.Trophy2.dll.sprx",
                                trophy2_system_symbols);

    logf("V52 probing Sce.Vsh.Np.TrophyAccessor system symbols");
    probe_shellcore_symbol_list("Sce.Vsh.Np.TrophyAccessor.dll.sprx",
                                trophy2_system_symbols);

    logf("V52 probing ReactNative trophy module system symbols");
    probe_shellcore_symbol_list("ReactNative.Modules.Vsh.Trophy.dll.sprx",
                                trophy2_system_symbols);

    logf("V52 probing Sce.Vsh.Np.Uds system symbols");
    probe_shellcore_symbol_list("Sce.Vsh.Np.Uds.dll.sprx",
                                uds_system_symbols);

    logf("V52 probing ShellCore promote symbols");
    probe_shellcore_symbol_list("SceShellCore.elf",
                                trophy_vsh_promote_symbols);

    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/trophy/data/sce_trop/trophy.img",
        "active_user_trophy_img");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/trophy/data/sce_trop/sealedkey",
        "active_user_sealedkey");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/np_uds/nobackup/events",
        "active_user_uds_events_dir");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/trophy2/nobackup/data/NPWR25716_00/TRPTITLE.DAT",
        "user0_goat_trptitle");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/np_uds/nobackup/stats/NPWR25716_00/stats.dat",
        "user0_goat_stats");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdb/np_uds/nobackup/events/PPSA04158_00/events.dat",
        "user0_goat_events");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdc/trophy2/nobackup/data/NPWR25716_00/TRPTITLE.DAT",
        "user1_goat_trptitle");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdc/np_uds/nobackup/stats/NPWR25716_00/stats.dat",
        "user1_goat_stats");
    probe_shellcore_trophy_path(
        "/user/home/179a0cdc/np_uds/nobackup/events/PPSA04158_00/events.dat",
        "user1_goat_events");
    probe_shellcore_trophy_path(
        "/system_data/priv/home/179a0cdb",
        "active_user_system_priv_home");
    probe_shellcore_trophy_path(
        "/system_data/priv/home/user_list.dat",
        "system_user_list");

    logf("V33 Shell diagnostic done: no writes, no unlock attempted");
    notify("trophy_unlocker: V33 Shell diag done");
}

static int
resolve_self_symbol(const char *module, const char *sym, void **slot)
{
    uint32_t h = 0;
    int r = kernel_dynlib_handle(getpid(), module, &h);
    if (r != 0 || h == 0) {
        logf("V22 resolve module=%s sym=%s handle failed rc=0x%08x h=0x%08x",
             module, sym, r, h);
        *slot = NULL;
        return -1;
    }

    intptr_t addr = kernel_dynlib_dlsym(getpid(), h, sym);
    *slot = (void *)addr;
    logf("V22 resolve module=%s sym=%s -> %p", module, sym, (void *)addr);
    return addr ? 0 : -1;
}

static int
resolve_optional_symbol_any(const char *sym, void **slot,
                            const char *const *modules)
{
    *slot = NULL;
    for (int i = 0; modules[i] != NULL; i++) {
        if (resolve_self_symbol(modules[i], sym, slot) == 0) {
            logf("V26 optional sym=%s resolved in %s -> %p",
                 sym, modules[i], *slot);
            return 0;
        }
    }

    logf("V26 optional sym=%s missing", sym);
    return -1;
}

static int
resolve_ps5_trophy2_uds_symbols(void)
{
    struct symbol_req {
        const char *module;
        const char *sym;
        void **slot;
    } user_reqs[] = {
        { "libSceUserService.sprx", "sceUserServiceGetInitialUser",
          (void **)&p_UserServiceGetInitialUser },
    };
    struct symbol_req trophy2_reqs[] = {
        { "libSceNpTrophy2.sprx", "sceNpTrophy2CreateHandle",
          (void **)&p_Trophy2CreateHandle },
        { "libSceNpTrophy2.sprx", "sceNpTrophy2DestroyHandle",
          (void **)&p_Trophy2DestroyHandle },
        { "libSceNpTrophy2.sprx", "sceNpTrophy2CreateContext",
          (void **)&p_Trophy2CreateContext },
        { "libSceNpTrophy2.sprx", "sceNpTrophy2DestroyContext",
          (void **)&p_Trophy2DestroyContext },
        { "libSceNpTrophy2.sprx", "sceNpTrophy2RegisterContext",
          (void **)&p_Trophy2RegisterContext },
        { "libSceNpTrophy2.sprx", "sceNpTrophy2GetGameInfo",
          (void **)&p_Trophy2GetGameInfo },
    };
    struct symbol_req uds_reqs[] = {
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemInitialize",
          (void **)&p_UdsInitialize },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemTerminate",
          (void **)&p_UdsTerminate },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemCreateContext",
          (void **)&p_UdsCreateContext },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemDestroyContext",
          (void **)&p_UdsDestroyContext },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemRegisterContext",
          (void **)&p_UdsRegisterContext },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemCreateHandle",
          (void **)&p_UdsCreateHandle },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemDestroyHandle",
          (void **)&p_UdsDestroyHandle },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemCreateEvent",
          (void **)&p_UdsCreateEvent },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemDestroyEvent",
          (void **)&p_UdsDestroyEvent },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemPostEvent",
          (void **)&p_UdsPostEvent },
        { "libSceNpUniversalDataSystem.sprx", "sceNpUniversalDataSystemEventPropertyObjectSetInt32",
          (void **)&p_UdsPropSetInt32 },
    };

    int missing_user = 0;
    int missing_trophy2 = 0;
    int missing_uds = 0;

    g_trophy2_symbols_ok = 0;
    g_uds_symbols_ok = 0;
    g_uds_only_mode = 0;

    notify("DEBUG V22: resolving PS5 Trophy2/UDS symbols");
    for (size_t i = 0; i < sizeof(user_reqs) / sizeof(user_reqs[0]); i++) {
        if (resolve_self_symbol(user_reqs[i].module,
                                user_reqs[i].sym,
                                user_reqs[i].slot) != 0) {
            missing_user++;
            notify("DEBUG V22: missing %.42s", user_reqs[i].sym);
        }
    }
    for (size_t i = 0; i < sizeof(trophy2_reqs) / sizeof(trophy2_reqs[0]); i++) {
        if (resolve_self_symbol(trophy2_reqs[i].module,
                                trophy2_reqs[i].sym,
                                trophy2_reqs[i].slot) != 0) {
            missing_trophy2++;
            notify("DEBUG V22: missing %.42s", trophy2_reqs[i].sym);
        }
    }
    for (size_t i = 0; i < sizeof(uds_reqs) / sizeof(uds_reqs[0]); i++) {
        if (resolve_self_symbol(uds_reqs[i].module,
                                uds_reqs[i].sym,
                                uds_reqs[i].slot) != 0) {
            missing_uds++;
            notify("DEBUG V22: missing %.42s", uds_reqs[i].sym);
        }
    }

    {
        static const char *const trophy2_modules[] = {
            "libSceNpTrophy2.sprx",
            NULL
        };
        static const char *const np_modules[] = {
            "libSceNpManager.sprx",
            "libSceNpUtility.sprx",
            "libSceNp.sprx",
            NULL
        };

        (void)resolve_optional_symbol_any("sceNpTrophy2RegisterUnlockCallback",
                                          (void **)&p_Trophy2RegisterUnlockCallback,
                                          trophy2_modules);
        (void)resolve_optional_symbol_any("sceNpTrophy2UnregisterUnlockCallback",
                                          (void **)&p_Trophy2UnregisterUnlockCallback,
                                          trophy2_modules);
        (void)resolve_optional_symbol_any("sceNpTrophy2GetTrophyInfo",
                                          (void **)&p_Trophy2GetTrophyInfo,
                                          trophy2_modules);
        (void)resolve_optional_symbol_any("sceNpTrophy2ShowTrophyList",
                                          (void **)&p_Trophy2ShowTrophyList,
                                          trophy2_modules);
        (void)resolve_optional_symbol_any("sceNpCheckCallback",
                                          (void **)&p_NpCheckCallback,
                                          np_modules);
    }

    g_trophy2_symbols_ok = missing_trophy2 == 0;
    g_uds_symbols_ok = missing_uds == 0;
    g_uds_only_mode = !g_trophy2_symbols_ok && g_uds_symbols_ok;

    if (missing_user != 0 || !g_uds_symbols_ok) {
        notify("trophy_unlocker: V22 resolve failed user=%d trophy2=%d uds=%d",
               missing_user, missing_trophy2, missing_uds);
        return -1;
    }

    if (g_trophy2_symbols_ok)
        notify("trophy_unlocker: V22 PS5 Trophy2+UDS symbols OK");
    else
        notify("trophy_unlocker: V67 UDS-only symbols OK trophy2_missing=%d",
               missing_trophy2);
    return 0;
}

static int
get_initial_user_id(SceUserServiceUserId *user_id)
{
    int rc;

    *user_id = SCE_USER_SERVICE_USER_ID_INVALID;
    if (p_UserServiceGetInitialUser == NULL)
        return -1;

    rc = p_UserServiceGetInitialUser(user_id);
    logf("V22 sceUserServiceGetInitialUser -> 0x%08x user=%d", rc, *user_id);
    notify("DEBUG V22: initial user rc=0x%08x user=%d", rc, *user_id);
    if (rc < 0 || *user_id == SCE_USER_SERVICE_USER_ID_INVALID)
        return -1;

    g_initial_user_id = *user_id;
    return 0;
}

static void
destroy_trophy2_pair(SceNpTrophy2Context *context, SceNpTrophy2Handle *handle,
                     const char *phase)
{
    int rc;

    if (*handle != SCE_NP_TROPHY2_INVALID_HANDLE) {
        rc = p_Trophy2DestroyHandle(*handle);
        logf("V27 Trophy2 DestroyHandle phase=%s h=%d -> 0x%08x",
             phase, *handle, rc);
        *handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    }

    if (*context != SCE_NP_TROPHY2_INVALID_CONTEXT) {
        rc = p_Trophy2DestroyContext(*context);
        logf("V27 Trophy2 DestroyContext phase=%s ctx=%d -> 0x%08x",
             phase, *context, rc);
        *context = SCE_NP_TROPHY2_INVALID_CONTEXT;
    }
}

static void
trophy2_post_unlock_diag(SceNpTrophy2Context context,
                         SceNpTrophy2Handle existing_handle,
                         int trophy_id,
                         const char *phase)
{
    SceNpTrophy2Handle handle = existing_handle;
    SceNpTrophy2GameDetails game_details;
    SceNpTrophy2GameData game_data;
    SceNpTrophy2Details trophy_details;
    SceNpTrophy2Data trophy_data;
    int own_handle = 0;
    int rc;

    if (context == SCE_NP_TROPHY2_INVALID_CONTEXT) {
        logf("V40 postdiag phase=%s skip: invalid Trophy2 context", phase);
        return;
    }

    if (handle == SCE_NP_TROPHY2_INVALID_HANDLE) {
        rc = p_Trophy2CreateHandle(&handle);
        logf("V40 postdiag phase=%s CreateHandle -> 0x%08x h=%d",
             phase, rc, handle);
        if (rc < 0)
            return;
        own_handle = 1;
    }

    memset(&game_details, 0, sizeof game_details);
    memset(&game_data, 0, sizeof game_data);
    rc = p_Trophy2GetGameInfo(context, handle, &game_details, &game_data);
    logf("V40 postdiag phase=%s ctx=%d h=%d GetGameInfo -> 0x%08x num=%u unlocked=%u progress=%u title='%.*s'",
         phase, context, handle, rc, game_details.numTrophies,
         game_data.unlockedTrophies, game_data.progressPercentage,
         64, game_details.title);
    notify("trophy_unlocker: V40 diag game rc=0x%08x unlocked=%u/%u",
           rc, game_data.unlockedTrophies, game_details.numTrophies);

    if (p_Trophy2GetTrophyInfo != NULL &&
        trophy_id != SCE_NP_TROPHY2_INVALID_TROPHY_ID) {
        memset(&trophy_details, 0, sizeof trophy_details);
        memset(&trophy_data, 0, sizeof trophy_data);
        rc = p_Trophy2GetTrophyInfo(context, handle,
                                    (SceNpTrophy2Id)trophy_id,
                                    &trophy_details, &trophy_data);
        logf("V40 postdiag phase=%s ctx=%d h=%d GetTrophyInfo id=%d -> 0x%08x unlocked=%u grade=%d group=%d progress_type=%d progress=%llu tick=%llu name='%.*s'",
             phase, context, handle, trophy_id, rc,
             trophy_data.unlocked ? 1U : 0U,
             trophy_details.trophyGrade, trophy_details.groupId,
             trophy_data.progress.type,
             (unsigned long long)trophy_data.progress.value.valueUInt64,
             (unsigned long long)trophy_data.timestamp.tick,
             64, trophy_details.name);
        notify("trophy_unlocker: V40 diag id=%d rc=0x%08x unlocked=%u",
               trophy_id, rc, trophy_data.unlocked ? 1U : 0U);
    } else {
        logf("V40 postdiag phase=%s GetTrophyInfo unavailable or invalid id=%d",
             phase, trophy_id);
    }

    if (ENABLE_TROPHY2_SHOW_LIST_AFTER_POST &&
        p_Trophy2ShowTrophyList != NULL) {
        rc = p_Trophy2ShowTrophyList(context);
        logf("V40 postdiag phase=%s ShowTrophyList ctx=%d -> 0x%08x",
             phase, context, rc);
        notify("trophy_unlocker: V40 ShowTrophyList rc=0x%08x", rc);
    }

    if (own_handle) {
        rc = p_Trophy2DestroyHandle(handle);
        logf("V40 postdiag phase=%s DestroyHandle h=%d -> 0x%08x",
             phase, handle, rc);
    }
}

static void
run_trophy2_post_info_diag(SceNpTrophy2Context trophy_ctx,
                           SceNpTrophy2Handle trophy_handle,
                           int lo,
                           int hi,
                           const char *phase)
{
    SceNpTrophy2Context diag_ctx = trophy_ctx;
    SceNpTrophy2Id diag_id = (SceNpTrophy2Id)lo;

    if (!ENABLE_TROPHY2_POST_INFO_DIAG)
        return;

    if (g_found_trophy2_context != SCE_NP_TROPHY2_INVALID_CONTEXT) {
        diag_ctx = g_found_trophy2_context;
        diag_id = (SceNpTrophy2Id)lo;
    } else if (diag_ctx == SCE_NP_TROPHY2_INVALID_CONTEXT &&
               g_trophy2_unlock_callbacks > 0) {
        diag_ctx = g_last_trophy2_unlock_context;
        diag_id = g_last_trophy2_unlock_id;
    }
    if (diag_ctx == SCE_NP_TROPHY2_INVALID_CONTEXT) {
        diag_ctx = (SceNpTrophy2Context)TROPHY2_LAST_SEEN_CONTEXT_FALLBACK;
        diag_id = (SceNpTrophy2Id)lo;
    }

    logf("V40 postdiag select phase=%s trophy_ctx=%d found_ctx=%d found_num=%u found_unlocked=%u accepted_uds=%d cb_count=%d cb_ctx=%d cb_id=%d diag_ctx=%d diag_id=%d",
         phase, trophy_ctx, g_found_trophy2_context,
         g_found_trophy2_num_trophies,
         g_found_trophy2_unlocked_trophies,
         g_last_accepted_uds_context, g_trophy2_unlock_callbacks,
         g_last_trophy2_unlock_context, g_last_trophy2_unlock_id,
         diag_ctx, diag_id);
    trophy2_post_unlock_diag(diag_ctx, trophy_handle, diag_id, phase);
    if (hi != lo)
        trophy2_post_unlock_diag(diag_ctx, trophy_handle, hi, phase);
}

static int
try_trophy2_service_label(SceUserServiceUserId user_id,
                          SceNpServiceLabel service_label,
                          SceNpTrophy2Context *context,
                          SceNpTrophy2Handle *handle,
                          uint32_t *num_trophies)
{
    SceNpTrophy2GameDetails details;
    SceNpTrophy2GameData data;
    int rc;

    *context = SCE_NP_TROPHY2_INVALID_CONTEXT;
    *handle = SCE_NP_TROPHY2_INVALID_HANDLE;

    rc = p_Trophy2CreateContext(context, user_id, service_label, 0);
    logf("V27 Trophy2 label=%u CreateContext -> 0x%08x ctx=%d",
         service_label, rc, *context);
    if (rc < 0)
        return rc;

    rc = p_Trophy2CreateHandle(handle);
    logf("V27 Trophy2 label=%u CreateHandle -> 0x%08x h=%d",
         service_label, rc, *handle);
    if (rc < 0) {
        destroy_trophy2_pair(context, handle, "label-handle-failed");
        return rc;
    }

    rc = p_Trophy2RegisterContext(*context, *handle, 0);
    logf("V27 Trophy2 label=%u RegisterContext -> 0x%08x",
         service_label, rc);
    if (rc < 0) {
        destroy_trophy2_pair(context, handle, "label-register-failed");
        return rc;
    }

    memset(&details, 0, sizeof details);
    memset(&data, 0, sizeof data);
    rc = p_Trophy2GetGameInfo(*context, *handle, &details, &data);
    logf("V27 Trophy2 label=%u GetGameInfo -> 0x%08x num=%u unlocked=%u title='%.*s'",
         service_label, rc, details.numTrophies, data.unlockedTrophies,
         64, details.title);
    if (rc >= 0 && num_trophies != NULL)
        *num_trophies = details.numTrophies;

    notify("trophy_unlocker: V27 Trophy2 label=%u OK trophies=%u",
           service_label, num_trophies != NULL ? *num_trophies : 0);
    return 0;
}

static int
scan_trophy2_service_labels(SceUserServiceUserId user_id,
                            SceNpTrophy2Context *context,
                            SceNpTrophy2Handle *handle,
                            uint32_t *num_trophies)
{
    int last_rc = -1;

    notify("trophy_unlocker: V27 scan Trophy2 labels 1..%d",
           NP_SERVICE_LABEL_SCAN_MAX);
    for (SceNpServiceLabel label = 1;
         label <= NP_SERVICE_LABEL_SCAN_MAX;
         label++) {
        last_rc = try_trophy2_service_label(user_id, label, context, handle,
                                            num_trophies);
        if (last_rc >= 0)
            return 0;
        sceKernelUsleep(20000);
    }

    logf("V27 Trophy2 service label scan failed last=0x%08x", last_rc);
    notify("trophy_unlocker: V27 aucun label Trophy2 OK");
    return last_rc;
}

static int
scan_existing_trophy2_contexts(uint32_t *num_trophies)
{
    SceNpTrophy2Handle handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    SceNpTrophy2GameDetails details;
    SceNpTrophy2GameData data;
    SceNpTrophy2Details trophy_details;
    SceNpTrophy2Data trophy_data;
    int invalid_contexts = 0;
    int not_registered = 0;
    int other_errors = 0;
    int rc;

    memset(g_seen_trophy_unlocked, 0, sizeof g_seen_trophy_unlocked);
    memset(g_seen_trophy_valid, 0, sizeof g_seen_trophy_valid);

    rc = p_Trophy2CreateHandle(&handle);
    logf("V29 Trophy2 scan CreateHandle -> 0x%08x h=%d", rc, handle);
    if (rc < 0)
        return rc;

    notify("trophy_unlocker: V29 scan Trophy2 ctx 0x%08x..0x%08x",
           TROPHY2_CONTEXT_SCAN_BASE,
           TROPHY2_CONTEXT_SCAN_BASE + TROPHY2_CONTEXT_SCAN_LIMIT - 1);

    for (int ctx = TROPHY2_CONTEXT_SCAN_BASE;
         ctx < TROPHY2_CONTEXT_SCAN_BASE + TROPHY2_CONTEXT_SCAN_LIMIT;
         ctx++) {
        memset(&details, 0, sizeof details);
        memset(&data, 0, sizeof data);
        rc = p_Trophy2GetGameInfo((SceNpTrophy2Context)ctx, handle,
                                  &details, &data);
        logf("V45 Trophy2 scan GetGameInfo ctx=0x%08x -> 0x%08x groups=%u num=%u p/g/s/b=%u/%u/%u/%u unlocked=%u up/ug/us/ub=%u/%u/%u/%u progress=%u title='%.*s'",
             ctx, rc, details.numGroups, details.numTrophies,
             details.numPlatinum, details.numGold, details.numSilver,
             details.numBronze, data.unlockedTrophies,
             data.unlockedPlatinum, data.unlockedGold,
             data.unlockedSilver, data.unlockedBronze,
             data.progressPercentage, 64, details.title);
        if (rc >= 0) {
            g_found_trophy2_context = (SceNpTrophy2Context)ctx;
            g_found_trophy2_num_trophies = details.numTrophies;
            g_found_trophy2_unlocked_trophies = data.unlockedTrophies;
            if (num_trophies != NULL)
                *num_trophies = details.numTrophies;
            notify("trophy_unlocker: V29 Trophy2 ctx=0x%08x OK trophies=%u unlocked=%u",
                   ctx, details.numTrophies, data.unlockedTrophies);
            if (p_Trophy2GetTrophyInfo != NULL) {
                uint32_t max_probe = details.numTrophies <
                    TROPHY2_SCAN_TROPHY_INFO_LIMIT ?
                    details.numTrophies : TROPHY2_SCAN_TROPHY_INFO_LIMIT;
                for (uint32_t id = 0; id < max_probe; id++) {
                    memset(&trophy_details, 0, sizeof trophy_details);
                    memset(&trophy_data, 0, sizeof trophy_data);
                    rc = p_Trophy2GetTrophyInfo((SceNpTrophy2Context)ctx,
                                                handle,
                                                (SceNpTrophy2Id)id,
                                                &trophy_details,
                                                &trophy_data);
                    logf("V45 Trophy2 scan GetTrophyInfo ctx=0x%08x id=%u -> 0x%08x unlocked=%u grade=%d group=%d hidden=%u progress_type=%d progress=%llu tick=%llu name='%.*s'",
                         ctx, id, rc, trophy_data.unlocked ? 1U : 0U,
                         trophy_details.trophyGrade, trophy_details.groupId,
                         trophy_details.hidden ? 1U : 0U,
                         trophy_data.progress.type,
                         (unsigned long long)trophy_data.progress.value.valueUInt64,
                         (unsigned long long)trophy_data.timestamp.tick,
                         64, trophy_details.name);
                    if (rc >= 0 && id < TROPHY_UNLOCKER_MAX_ALL) {
                        g_seen_trophy_valid[id] = 1;
                        g_seen_trophy_unlocked[id] =
                            trophy_data.unlocked ? 1 : 0;
                    }
                    if (id < 4 || trophy_data.unlocked)
                        notify("trophy_unlocker: V45 id=%u rc=0x%08x unlocked=%u",
                               id, rc, trophy_data.unlocked ? 1U : 0U);
                    sceKernelUsleep(20000);
                }
            }
            if (ENABLE_TROPHY2_SHOW_LIST_IN_SCAN &&
                p_Trophy2ShowTrophyList != NULL) {
                rc = p_Trophy2ShowTrophyList((SceNpTrophy2Context)ctx);
                logf("V43 Trophy2 scan ShowTrophyList ctx=0x%08x -> 0x%08x",
                     ctx, rc);
                notify("trophy_unlocker: V43 ShowTrophyList rc=0x%08x",
                       rc);
                pump_np_callbacks("after-show-trophy-list", 8);
                sceKernelUsleep(1000000);
            }
            p_Trophy2DestroyHandle(handle);
            return ctx;
        }

        switch ((uint32_t)rc) {
        case 0x80553904U:
            invalid_contexts++;
            break;
        case 0x80553920U:
            not_registered++;
            break;
        default:
            other_errors++;
            break;
        }
        sceKernelUsleep(5000);
    }

    logf("V29 Trophy2 scan no context invalid=%d not_registered=%d other=%d",
         invalid_contexts, not_registered, other_errors);
    notify("trophy_unlocker: V29 aucun contexte Trophy2 OK");
    p_Trophy2DestroyHandle(handle);
    return -1;
}

typedef struct Trophy2ThreadProbe {
    SceUserServiceUserId user_id;
    volatile int done;
    int create_context_rc;
    int create_handle_rc;
    int register_rc;
    int get_info_rc;
    SceNpTrophy2Context context;
    SceNpTrophy2Handle handle;
    uint32_t num_trophies;
    uint32_t unlocked_trophies;
    char title[64];
} Trophy2ThreadProbe;

static void *
trophy2_register_probe_thread(void *arg)
{
    Trophy2ThreadProbe *probe = (Trophy2ThreadProbe *)arg;
    SceNpTrophy2GameDetails details;
    SceNpTrophy2GameData data;
    int rc;

    probe->context = SCE_NP_TROPHY2_INVALID_CONTEXT;
    probe->handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    probe->create_context_rc = 0x7fffffff;
    probe->create_handle_rc = 0x7fffffff;
    probe->register_rc = 0x7fffffff;
    probe->get_info_rc = 0x7fffffff;

    logf("V30 thread Trophy2 probe start user=%d", probe->user_id);
    notify("trophy_unlocker: V30 thread Trophy2 start");

    rc = p_Trophy2CreateContext(&probe->context, probe->user_id, 0, 0);
    probe->create_context_rc = rc;
    logf("V30 thread Trophy2 CreateContext -> 0x%08x ctx=%d",
         rc, probe->context);
    if (rc < 0)
        goto out;

    rc = p_Trophy2CreateHandle(&probe->handle);
    probe->create_handle_rc = rc;
    logf("V30 thread Trophy2 CreateHandle -> 0x%08x h=%d",
         rc, probe->handle);
    if (rc < 0)
        goto out;

    pump_np_callbacks("v30-thread-before-register", 2);
    rc = p_Trophy2RegisterContext(probe->context, probe->handle, 0);
    probe->register_rc = rc;
    logf("V30 thread Trophy2 RegisterContext -> 0x%08x", rc);
    notify("trophy_unlocker: V30 thread Register rc=0x%08x", rc);
    pump_np_callbacks("v30-thread-after-register", 6);
    if (rc < 0)
        goto out;

    memset(&details, 0, sizeof details);
    memset(&data, 0, sizeof data);
    rc = p_Trophy2GetGameInfo(probe->context, probe->handle,
                              &details, &data);
    probe->get_info_rc = rc;
    probe->num_trophies = details.numTrophies;
    probe->unlocked_trophies = data.unlockedTrophies;
    memcpy(probe->title, details.title, sizeof probe->title - 1);
    probe->title[sizeof probe->title - 1] = '\0';
    logf("V30 thread Trophy2 GetGameInfo -> 0x%08x num=%u unlocked=%u title='%.*s'",
         rc, details.numTrophies, data.unlockedTrophies, 64, details.title);
    notify("trophy_unlocker: V30 Trophy2 OK trophies=%u unlocked=%u",
           details.numTrophies, data.unlockedTrophies);

out:
    if (probe->handle != SCE_NP_TROPHY2_INVALID_HANDLE) {
        rc = p_Trophy2DestroyHandle(probe->handle);
        logf("V30 thread Trophy2 DestroyHandle h=%d -> 0x%08x",
             probe->handle, rc);
        probe->handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    }
    if (probe->context != SCE_NP_TROPHY2_INVALID_CONTEXT) {
        rc = p_Trophy2DestroyContext(probe->context);
        logf("V30 thread Trophy2 DestroyContext ctx=%d -> 0x%08x",
             probe->context, rc);
        probe->context = SCE_NP_TROPHY2_INVALID_CONTEXT;
    }

    logf("V30 thread Trophy2 probe done create=0x%08x handle=0x%08x register=0x%08x info=0x%08x",
         probe->create_context_rc, probe->create_handle_rc,
         probe->register_rc, probe->get_info_rc);
    probe->done = 1;
    return NULL;
}

static int
run_threaded_trophy2_register_probe(SceUserServiceUserId user_id,
                                    uint32_t *num_trophies)
{
    static Trophy2ThreadProbe probe;
    ScePthread th;
    int rc;

    memset(&probe, 0, sizeof probe);
    probe.user_id = user_id;

    rc = scePthreadCreate(&th, NULL, trophy2_register_probe_thread,
                          &probe, "trophy2_probe");
    logf("V30 scePthreadCreate(trophy2_probe) -> 0x%08x th=%p", rc, th);
    notify("trophy_unlocker: V30 create thread rc=0x%08x", rc);
    if (rc < 0)
        return rc;

    scePthreadDetach(th);
    for (int waited = 0; waited < TROPHY2_THREAD_WAIT_MS; waited += 100) {
        if (probe.done)
            break;
        pump_np_callbacks("v30-main-wait-thread", 1);
        sceKernelUsleep(100000);
    }

    if (!probe.done) {
        logf("V30 Trophy2 threaded probe timeout after %d ms",
             TROPHY2_THREAD_WAIT_MS);
        notify("trophy_unlocker: V30 thread timeout");
        return -1;
    }

    if (probe.get_info_rc >= 0 && num_trophies != NULL)
        *num_trophies = probe.num_trophies;

    logf("V30 threaded result create=0x%08x handle=0x%08x register=0x%08x info=0x%08x num=%u unlocked=%u title='%.*s'",
         probe.create_context_rc, probe.create_handle_rc, probe.register_rc,
         probe.get_info_rc, probe.num_trophies, probe.unlocked_trophies,
         64, probe.title);

    if (probe.register_rc != 0x7fffffff)
        return probe.register_rc;
    if (probe.create_handle_rc != 0x7fffffff)
        return probe.create_handle_rc;
    return probe.create_context_rc;
}

typedef struct CandidateCounter {
    uint32_t value;
    uint32_t count;
} CandidateCounter;

typedef struct HeapScanResult {
    uint32_t ctx;
    uint32_t ctx_count;
    uint32_t handle;
    uint32_t handle_count;
} HeapScanResult;

static HeapScanResult g_trophy2_heap_result;
static HeapScanResult g_uds_heap_result;

static void
remember_candidate(CandidateCounter *slots, uint32_t value)
{
    int empty = -1;

    for (int i = 0; i < V31_CANDIDATE_MAX; i++) {
        if (slots[i].count != 0 && slots[i].value == value) {
            slots[i].count++;
            return;
        }
        if (empty < 0 && slots[i].count == 0)
            empty = i;
    }

    if (empty >= 0) {
        slots[empty].value = value;
        slots[empty].count = 1;
    }
}

static CandidateCounter
best_candidate(const CandidateCounter *slots)
{
    CandidateCounter best;

    best.value = 0;
    best.count = 0;

    for (int i = 0; i < V31_CANDIDATE_MAX; i++) {
        if (slots[i].count > best.count)
            best = slots[i];
    }

    return best;
}

static void
log_candidate_slots(const char *tag, const char *kind,
                    const CandidateCounter *slots)
{
    for (int printed = 0; printed < 16; printed++) {
        int best = -1;

        for (int i = 0; i < V31_CANDIDATE_MAX; i++) {
            if (slots[i].count == 0)
                continue;
            if (best < 0 || slots[i].count > slots[best].count)
                best = i;
        }

        if (best < 0)
            break;

        logf("V31 %s %s candidate value=0x%08x count=%u",
             tag, kind, slots[best].value, slots[best].count);

        ((CandidateCounter *)slots)[best].count = 0;
    }
}

static void
scan_candidate_heap(const char *tag, uintptr_t start, size_t size,
                    HeapScanResult *result)
{
    CandidateCounter ctx[V31_CANDIDATE_MAX];
    CandidateCounter handle[V31_CANDIDATE_MAX];
    uint32_t ctx_seen = 0;
    uint32_t handle_seen = 0;

    memset(ctx, 0, sizeof ctx);
    memset(handle, 0, sizeof handle);
    if (result != NULL)
        memset(result, 0, sizeof *result);

    logf("V31 scan %s heap start=%p size=0x%zx", tag, (void *)start, size);

    for (size_t off = 0; off + sizeof(uint32_t) <= size; off += sizeof(uint32_t)) {
        uint32_t value = *(volatile uint32_t *)(start + off);

        if (value >= 0x00040000U && value <= 0x00041000U) {
            remember_candidate(ctx, value);
            ctx_seen++;
        }
        if (value >= 0x00020000U && value <= 0x00021000U) {
            remember_candidate(handle, value);
            handle_seen++;
        }
    }

    logf("V31 scan %s totals ctx_like=%u handle_like=%u",
         tag, ctx_seen, handle_seen);

    if (result != NULL) {
        CandidateCounter best_ctx = best_candidate(ctx);
        CandidateCounter best_handle = best_candidate(handle);
        result->ctx = best_ctx.value;
        result->ctx_count = best_ctx.count;
        result->handle = best_handle.value;
        result->handle_count = best_handle.count;
    }

    if (ctx_seen == 0)
        logf("V31 %s ctx candidate none", tag);
    else
        log_candidate_slots(tag, "ctx", ctx);

    if (handle_seen == 0)
        logf("V31 %s handle candidate none", tag);
    else
        log_candidate_slots(tag, "handle", handle);
}

static void
scan_known_np_heaps_for_candidates(void)
{
    notify("trophy_unlocker: V31 scan heap ctx/handle");
    scan_candidate_heap("Trophy2", (uintptr_t)TROPHY2_HEAP_SCAN_START,
                        (size_t)TROPHY2_HEAP_SCAN_SIZE,
                        &g_trophy2_heap_result);
    scan_candidate_heap("UDS", (uintptr_t)UDS_HEAP_SCAN_START,
                        (size_t)UDS_HEAP_SCAN_SIZE,
                        &g_uds_heap_result);
}

static void
test_trophy2_candidate_get_info(uint32_t *num_trophies)
{
    SceNpTrophy2GameDetails details;
    SceNpTrophy2GameData data;
    SceNpTrophy2Handle new_handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    int rc;

    if (g_trophy2_heap_result.ctx == 0) {
        logf("V32 Trophy2 candidate test skipped: no ctx candidate");
        notify("trophy_unlocker: V32 aucun ctx Trophy2 candidat");
        return;
    }

    notify("trophy_unlocker: V32 test Trophy2 ctx=0x%08x",
           g_trophy2_heap_result.ctx);

    rc = p_Trophy2CreateHandle(&new_handle);
    logf("V32 Trophy2 candidate CreateHandle -> 0x%08x h=0x%08x",
         rc, (uint32_t)new_handle);
    if (rc >= 0) {
        memset(&details, 0, sizeof details);
        memset(&data, 0, sizeof data);
        rc = p_Trophy2GetGameInfo((SceNpTrophy2Context)g_trophy2_heap_result.ctx,
                                  new_handle, &details, &data);
        logf("V32 Trophy2 candidate GetGameInfo new_handle ctx=0x%08x h=0x%08x -> 0x%08x num=%u unlocked=%u title='%.*s'",
             g_trophy2_heap_result.ctx, (uint32_t)new_handle, rc,
             details.numTrophies, data.unlockedTrophies, 64, details.title);
        notify("trophy_unlocker: V32 Trophy2 GetInfo rc=0x%08x trophies=%u",
               rc, details.numTrophies);
        if (rc >= 0 && num_trophies != NULL)
            *num_trophies = details.numTrophies;

        rc = p_Trophy2DestroyHandle(new_handle);
        logf("V32 Trophy2 candidate DestroyHandle h=0x%08x -> 0x%08x",
             (uint32_t)new_handle, rc);
    }

    if (ENABLE_TROPHY2_CANDIDATE_HANDLE_TEST &&
        g_trophy2_heap_result.handle != 0) {
        memset(&details, 0, sizeof details);
        memset(&data, 0, sizeof data);
        rc = p_Trophy2GetGameInfo((SceNpTrophy2Context)g_trophy2_heap_result.ctx,
                                  (SceNpTrophy2Handle)g_trophy2_heap_result.handle,
                                  &details, &data);
        logf("V32 Trophy2 candidate GetGameInfo candidate_handle ctx=0x%08x h=0x%08x -> 0x%08x num=%u unlocked=%u title='%.*s'",
             g_trophy2_heap_result.ctx, g_trophy2_heap_result.handle, rc,
             details.numTrophies, data.unlockedTrophies, 64, details.title);
        notify("trophy_unlocker: V32 Trophy2 cand handle rc=0x%08x trophies=%u",
               rc, details.numTrophies);
    }
}

static void
destroy_uds_pair(SceNpUniversalDataSystemContext *context,
                 SceNpUniversalDataSystemHandle *handle,
                 const char *phase)
{
    int rc;

    if (*handle != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE) {
        rc = p_UdsDestroyHandle(*handle);
        logf("V27 UDS DestroyHandle phase=%s h=%d -> 0x%08x",
             phase, *handle, rc);
        *handle = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;
    }

    if (*context != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT) {
        rc = p_UdsDestroyContext(*context);
        logf("V27 UDS DestroyContext phase=%s ctx=%d -> 0x%08x",
             phase, *context, rc);
        *context = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    }
}

static int
try_uds_service_label(SceUserServiceUserId user_id,
                      SceNpServiceLabel service_label,
                      SceNpUniversalDataSystemContext *context,
                      SceNpUniversalDataSystemHandle *handle)
{
    int rc;

    *context = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    *handle = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;

    rc = p_UdsCreateContext(context, user_id, service_label, 0);
    logf("V27 UDS label=%u CreateContext -> 0x%08x ctx=%d",
         service_label, rc, *context);
    if (rc < 0)
        return rc;

    rc = p_UdsCreateHandle(handle);
    logf("V27 UDS label=%u CreateHandle(register) -> 0x%08x h=%d",
         service_label, rc, *handle);
    if (rc < 0) {
        destroy_uds_pair(context, handle, "label-handle-failed");
        return rc;
    }

    rc = p_UdsRegisterContext(*context, *handle, 0);
    logf("V27 UDS label=%u RegisterContext -> 0x%08x",
         service_label, rc);
    if (rc < 0) {
        destroy_uds_pair(context, handle, "label-register-failed");
        return rc;
    }

    notify("trophy_unlocker: V27 UDS label=%u OK", service_label);
    return 0;
}

static int
scan_uds_service_labels(SceUserServiceUserId user_id,
                        SceNpUniversalDataSystemContext *context,
                        SceNpUniversalDataSystemHandle *handle,
                        SceNpServiceLabel *selected_label)
{
    int last_rc = -1;

    notify("trophy_unlocker: V27 scan UDS labels 1..%d",
           NP_SERVICE_LABEL_SCAN_MAX);
    for (SceNpServiceLabel label = 1;
         label <= NP_SERVICE_LABEL_SCAN_MAX;
         label++) {
        last_rc = try_uds_service_label(user_id, label, context, handle);
        if (last_rc >= 0) {
            if (selected_label != NULL)
                *selected_label = label;
            return 0;
        }
        sceKernelUsleep(20000);
    }

    logf("V27 UDS service label scan failed last=0x%08x", last_rc);
    notify("trophy_unlocker: V27 aucun label UDS OK");
    return last_rc;
}

static char *
trim_selection(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;

    end = s + strlen(s);
    while (end > s &&
           (end[-1] == ' ' || end[-1] == '\t' ||
            end[-1] == '\r' || end[-1] == '\n')) {
        *--end = '\0';
    }

    return s;
}

static int
read_selection_file(char *buf, size_t bufsz)
{
    int fd;
    int n;

    if (bufsz == 0)
        return -1;

    fd = open(TROPHY_UNLOCKER_ID_FILE, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n <= 0)
        return -1;

    buf[n] = '\0';
    return 0;
}

static int
selection_max_id(uint32_t num_trophies)
{
    if (num_trophies > 0 && num_trophies <= TROPHY_UNLOCKER_MAX_ALL)
        return (int)num_trophies - 1;
    if (num_trophies > TROPHY_UNLOCKER_MAX_ALL)
        return TROPHY_UNLOCKER_MAX_ALL - 1;
    return -1;
}

static int
parse_positive_long(const char *s, long *value, const char **end_out)
{
    char *endp;
    long v;

    while (*s == ' ' || *s == '\t')
        s++;

    v = strtol(s, &endp, 10);
    if (endp == s)
        return -1;

    while (*endp == ' ' || *endp == '\t' || *endp == '\r' || *endp == '\n')
        endp++;

    *value = v;
    *end_out = endp;
    return 0;
}

static int
ascii_lower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static int
streq_ci(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (ascii_lower((unsigned char)*a) != ascii_lower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static void
copy_config_value(char *dst, size_t dstsz, const char *src)
{
    size_t i = 0;

    if (dstsz == 0)
        return;

    while (src[i] != '\0' && i + 1 < dstsz) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static int
read_config_selection(char *out, size_t outsz, uint32_t num_trophies)
{
    char buf[512];
    char mode[24] = {0};
    char id[24] = {0};
    char range[32] = {0};
    char start[24] = {0};
    char end[24] = {0};
    char wave[24] = {0};
    char *line;
    int fd;
    int n;
    int max_id;

    if (outsz == 0)
        return -1;

    fd = open(TROPHY_UNLOCKER_CONFIG_FILE, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    line = buf;
    while (*line != '\0') {
        char *next = line;
        char *hash;
        char *semi;
        char *eq;
        char *key;
        char *value;

        while (*next != '\0' && *next != '\n')
            next++;
        if (*next == '\n')
            *next++ = '\0';

        key = trim_selection(line);
        if (*key == '\0' || *key == '#' || *key == ';') {
            line = next;
            continue;
        }

        eq = strchr(key, '=');
        if (eq == NULL) {
            line = next;
            continue;
        }
        *eq = '\0';
        value = trim_selection(eq + 1);
        key = trim_selection(key);

        hash = strchr(value, '#');
        semi = strchr(value, ';');
        if (hash != NULL && (semi == NULL || hash < semi))
            *hash = '\0';
        else if (semi != NULL)
            *semi = '\0';
        value = trim_selection(value);

        if (streq_ci(key, "mode"))
            copy_config_value(mode, sizeof mode, value);
        else if (streq_ci(key, "id") || streq_ci(key, "trophy"))
            copy_config_value(id, sizeof id, value);
        else if (streq_ci(key, "range"))
            copy_config_value(range, sizeof range, value);
        else if (streq_ci(key, "start") || streq_ci(key, "from"))
            copy_config_value(start, sizeof start, value);
        else if (streq_ci(key, "end") || streq_ci(key, "to"))
            copy_config_value(end, sizeof end, value);
        else if (streq_ci(key, "wave") || streq_ci(key, "vague"))
            copy_config_value(wave, sizeof wave, value);

        line = next;
    }

    if (mode[0] == '\0') {
        if (range[0] != '\0')
            copy_config_value(mode, sizeof mode, "range");
        else if (id[0] != '\0')
            copy_config_value(mode, sizeof mode, "id");
        else if (wave[0] != '\0')
            copy_config_value(mode, sizeof mode, "wave");
        else
            return -1;
    }

    if (streq_ci(mode, "all") || streq_ci(mode, "tout")) {
        snprintf(out, outsz, "all");
    } else if (streq_ci(mode, "id") || streq_ci(mode, "one") ||
               streq_ci(mode, "single") || streq_ci(mode, "un")) {
        if (id[0] == '\0')
            return -1;
        snprintf(out, outsz, "%s", id);
    } else if (streq_ci(mode, "range") || streq_ci(mode, "plage")) {
        if (range[0] != '\0') {
            snprintf(out, outsz, "%s", range);
        } else if (start[0] != '\0' && end[0] != '\0') {
            snprintf(out, outsz, "%s-%s", start, end);
        } else {
            return -1;
        }
    } else if (streq_ci(mode, "wave") || streq_ci(mode, "vague")) {
        const char *tail;
        long first = 0;
        long count;
        long last;

        if (wave[0] == '\0')
            return -1;
        if (parse_positive_long(wave, &count, &tail) != 0 ||
            *tail != '\0' || count <= 0)
            return -1;
        if (start[0] != '\0' &&
            (parse_positive_long(start, &first, &tail) != 0 ||
             *tail != '\0' || first < 0))
            return -1;

        max_id = selection_max_id(num_trophies);
        if (max_id < 0 || first > max_id)
            return -1;
        last = first + count - 1;
        if (last > max_id)
            last = max_id;
        snprintf(out, outsz, "%ld-%ld", first, last);
    } else {
        return -1;
    }

    notify("trophy_unlocker: config %s -> %s", mode, out);
    logf("V90 config file %s mode='%s' id='%s' range='%s' start='%s' wave='%s' -> '%s'",
         TROPHY_UNLOCKER_CONFIG_FILE, mode, id, range, start, wave, out);
    return 0;
}

static int
parse_unlock_selection(const char *sel, uint32_t num_trophies, int *lo, int *hi)
{
    char *endp;
    const char *tail;
    const char *dash;
    long id;
    long first;
    long last;
    int max_id = selection_max_id(num_trophies);

    if (strcmp(sel, "all") == 0 || strcmp(sel, "ALL") == 0) {
        if (max_id < 0) {
            logf("V68 refusing all: trophy count unknown");
            return -1;
        }
        *lo = 0;
        *hi = max_id;
        return 0;
    }

    if (strncmp(sel, "count=", 6) == 0 || strncmp(sel, "COUNT=", 6) == 0 ||
        strncmp(sel, "count:", 6) == 0 || strncmp(sel, "COUNT:", 6) == 0) {
        if (parse_positive_long(sel + 6, &id, &tail) != 0 ||
            *tail != '\0' || id <= 0 || id > TROPHY_UNLOCKER_MAX_ALL ||
            (max_id >= 0 && id > max_id + 1))
            return -1;
        *lo = 0;
        *hi = (int)id - 1;
        return 0;
    }

    dash = strchr(sel, '-');
    if (dash != NULL) {
        if (parse_positive_long(sel, &first, &tail) != 0 ||
            tail != dash)
            return -1;
        if (parse_positive_long(dash + 1, &last, &tail) != 0 ||
            *tail != '\0')
            return -1;
        if (first < 0 || last < first ||
            last > (max_id >= 0 ? max_id : TROPHY_UNLOCKER_MAX_ALL - 1))
            return -1;
        *lo = (int)first;
        *hi = (int)last;
        return 0;
    }

    id = strtol(sel, &endp, 10);
    while (*endp == ' ' || *endp == '\t' || *endp == '\r' || *endp == '\n')
        endp++;

    if (sel[0] == '\0' || *endp != '\0' || id < 0 ||
        id > (max_id >= 0 ? max_id : TROPHY_UNLOCKER_MAX_ALL - 1))
        return -1;

    *lo = (int)id;
    *hi = (int)id;
    return 0;
}

static int
select_unlock_range(int argc, char *argv[], uint32_t num_trophies, int *lo, int *hi)
{
    char file_buf[64];
    char config_buf[96];
    char *sel = NULL;

    if (FORCE_TROPHY_ID_FOR_DIAG >= 0) {
        *lo = FORCE_TROPHY_ID_FOR_DIAG;
        *hi = FORCE_TROPHY_ID_FOR_DIAG;
        notify("trophy_unlocker: V41 forced diag trophy id %d",
               FORCE_TROPHY_ID_FOR_DIAG);
        logf("V41 forced diag trophy id=%d ignores argv/file for this build",
             FORCE_TROPHY_ID_FOR_DIAG);
        return 0;
    }

    if (argc >= 3)
        sel = argv[2];
    else if (argc >= 2)
        sel = argv[1];

    if (sel == NULL &&
        read_config_selection(config_buf, sizeof config_buf, num_trophies) == 0)
        sel = trim_selection(config_buf);

    if (sel == NULL && read_selection_file(file_buf, sizeof file_buf) == 0)
        sel = trim_selection(file_buf);

    if (sel == NULL || sel[0] == '\0') {
        int max_id = selection_max_id(num_trophies);
        if (max_id < 0) {
            notify("trophy_unlocker: V68 compteur trophees inconnu");
            logf("V68 no arg/file but trophy count is unknown; refusing default all");
            return -1;
        }
        *lo = 0;
        *hi = max_id;
        notify("trophy_unlocker: V47 default all -> %d..%d", *lo, *hi);
        logf("V47 no arg/file; default all -> %d..%d. Use %s with an id to target one trophy.",
             *lo, *hi, TROPHY_UNLOCKER_ID_FILE);
        return 0;
    }

    sel = trim_selection(sel);
    if (parse_unlock_selection(sel, num_trophies, lo, hi) != 0) {
        notify("trophy_unlocker: bad trophy selection '%s'", sel);
        return -1;
    }

    notify("trophy_unlocker: V22 selection '%s' -> %d..%d", sel, *lo, *hi);
    return 0;
}

static int
post_unlock_trophy_event(SceNpUniversalDataSystemContext context, int trophy_id)
{
    SceNpUniversalDataSystemHandle handle = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;
    SceNpUniversalDataSystemEvent *event = NULL;
    SceNpUniversalDataSystemEventPropertyObject *prop = NULL;
    int rc;
    int ret = 0;

    rc = p_UdsCreateHandle(&handle);
    logf("V22 UDS CreateHandle(event %d) -> 0x%08x h=%d", trophy_id, rc, handle);
    if (rc < 0)
        return rc;

    rc = p_UdsCreateEvent("_UnlockTrophy", NULL, &event, &prop);
    logf("V22 UDS CreateEvent(_UnlockTrophy id=%d) -> 0x%08x event=%p prop=%p",
         trophy_id, rc, event, prop);
    if (rc < 0) {
        ret = rc;
        goto out;
    }

    rc = p_UdsPropSetInt32(prop, "_trophy_id", trophy_id);
    logf("V22 UDS SetInt32(_trophy_id=%d) -> 0x%08x", trophy_id, rc);
    if (rc < 0) {
        ret = rc;
        goto out;
    }

    rc = p_UdsPostEvent(context, handle, event,
                        SCE_NP_UNIVERSAL_DATA_SYSTEM_POST_EVENT_OPTION_GENERATED_BY_CODEGEN);
    logf("V40 UDS PostEvent(_UnlockTrophy id=%d, opt=codegen-first) -> 0x%08x",
         trophy_id, rc);
    ret = rc;

    if (rc < 0) {
        int rc_plain = p_UdsPostEvent(context, handle, event, 0);
        logf("V40 UDS PostEvent(_UnlockTrophy id=%d, opt=0-fallback) -> 0x%08x",
             trophy_id, rc_plain);

        if (rc_plain >= 0 ||
            (uint32_t)ret == UDS_ERROR_INVALID_ARGUMENT_RC) {
            ret = rc_plain;
        }
    }

out:
    if (event != NULL) {
        rc = p_UdsDestroyEvent(event);
        logf("V22 UDS DestroyEvent(id=%d) -> 0x%08x", trophy_id, rc);
    }
    if (handle != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE) {
        rc = p_UdsDestroyHandle(handle);
        logf("V22 UDS DestroyHandle(event id=%d) -> 0x%08x", trophy_id, rc);
    }
    return ret;
}

static uint8_t g_uds_postevent_saved[UDS_HOOK_PATCH_LEN];
static int g_uds_postevent_saved_valid;
static volatile int g_uds_postevent_hook_installed;
static volatile int g_uds_postevent_hook_busy;
static uint8_t g_uds_createevent_saved[UDS_HOOK_PATCH_LEN];
static int g_uds_createevent_saved_valid;
static volatile int g_uds_createevent_hook_installed;
static volatile int g_uds_createevent_hook_busy;
static uint8_t g_uds_setint32_saved[UDS_HOOK_PATCH_LEN];
static int g_uds_setint32_saved_valid;
static volatile int g_uds_setint32_hook_installed;
static volatile int g_uds_setint32_hook_busy;
static volatile int g_uds_postevent_hook_calls;
static volatile int g_uds_postevent_hook_posted_all;
static volatile int g_uds_postevent_hook_post_ok;
static volatile int g_uds_postevent_hook_post_errors;
static volatile int g_live_post_lo = GOAT_TROPHY_MIN_ID;
static volatile int g_live_post_hi = GOAT_TROPHY_MAX_ID;
static volatile SceNpUniversalDataSystemContext g_uds_live_context =
    SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
static volatile SceNpUniversalDataSystemHandle g_uds_live_handle =
    SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;

typedef struct UdsTraceEventSlot {
    const SceNpUniversalDataSystemEvent *event;
    SceNpUniversalDataSystemEventPropertyObject *prop;
    char name[UDS_TRACE_NAME_MAX];
} UdsTraceEventSlot;

static UdsTraceEventSlot g_uds_trace_events[UDS_TRACE_EVENT_SLOTS];
static int g_uds_trace_next;

static int hooked_uds_post_event(SceNpUniversalDataSystemContext context,
                                 SceNpUniversalDataSystemHandle handle,
                                 const SceNpUniversalDataSystemEvent *event,
                                 uint64_t options);
static int hooked_uds_create_event(const char *name,
                                   const SceNpUniversalDataSystemEventPropertyObject *initial_prop,
                                   SceNpUniversalDataSystemEvent **event_out,
                                   SceNpUniversalDataSystemEventPropertyObject **prop_out);
static int hooked_uds_set_int32(SceNpUniversalDataSystemEventPropertyObject *prop,
                                const char *key,
                                int32_t value);

static void
copy_trace_name(char *dst, size_t dst_size, const char *src)
{
    size_t i;

    if (dst_size == 0)
        return;
    if (src == NULL) {
        dst[0] = '\0';
        return;
    }

    for (i = 0; i + 1 < dst_size && src[i] != '\0'; i++)
        dst[i] = src[i];
    dst[i] = '\0';
}

static void
uds_trace_reset(void)
{
    memset(g_uds_trace_events, 0, sizeof g_uds_trace_events);
    g_uds_trace_next = 0;
}

static void
uds_trace_store(const SceNpUniversalDataSystemEvent *event,
                SceNpUniversalDataSystemEventPropertyObject *prop,
                const char *name)
{
    int slot;

    if (event == NULL && prop == NULL)
        return;

    slot = g_uds_trace_next++ % UDS_TRACE_EVENT_SLOTS;
    g_uds_trace_events[slot].event = event;
    g_uds_trace_events[slot].prop = prop;
    copy_trace_name(g_uds_trace_events[slot].name,
                    sizeof g_uds_trace_events[slot].name,
                    name);
}

static const char *
uds_trace_name_for_event(const SceNpUniversalDataSystemEvent *event)
{
    for (int i = 0; i < UDS_TRACE_EVENT_SLOTS; i++) {
        if (g_uds_trace_events[i].event == event &&
            g_uds_trace_events[i].name[0] != '\0')
            return g_uds_trace_events[i].name;
    }
    return "?";
}

static const char *
uds_trace_name_for_prop(const SceNpUniversalDataSystemEventPropertyObject *prop)
{
    for (int i = 0; i < UDS_TRACE_EVENT_SLOTS; i++) {
        if (g_uds_trace_events[i].prop == prop &&
            g_uds_trace_events[i].name[0] != '\0')
            return g_uds_trace_events[i].name;
    }
    return "?";
}

static void
log_uds_event_bytes(const char *tag,
                    const SceNpUniversalDataSystemEvent *event)
{
    const unsigned char *p = (const unsigned char *)event;

    if (event == NULL) {
        logf("%s event=NULL", tag);
        return;
    }

    logf("%s event=%p bytes[00..1f]=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
         tag, event,
         p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
         p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15],
         p[16], p[17], p[18], p[19], p[20], p[21], p[22], p[23],
         p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31]);
    logf("%s event=%p bytes[20..3f]=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
         tag, event,
         p[32], p[33], p[34], p[35], p[36], p[37], p[38], p[39],
         p[40], p[41], p[42], p[43], p[44], p[45], p[46], p[47],
         p[48], p[49], p[50], p[51], p[52], p[53], p[54], p[55],
         p[56], p[57], p[58], p[59], p[60], p[61], p[62], p[63]);
}

static int
patch_uds_postevent_hook(int install)
{
    uint8_t patch[UDS_HOOK_PATCH_LEN];
    uintptr_t target;
    uintptr_t page;
    int rc;

    if (p_UdsPostEvent == NULL)
        return -1;

    target = (uintptr_t)p_UdsPostEvent;
    page = target & ~(uintptr_t)(UDS_HOOK_PAGE_SIZE - 1);

    if (install) {
        uintptr_t hook = (uintptr_t)hooked_uds_post_event;

        if (g_uds_postevent_hook_installed)
            return 0;

        logf("V63 hook PostEvent prepare target=%p page=%p hook=%p",
             (void *)target, (void *)page, (void *)hook);

        rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                             PROT_READ | PROT_WRITE | PROT_EXEC);
        logf("V64 hook install mprotect before save page=%p -> 0x%08x",
             (void *)page, rc);
        if (rc < 0)
            return rc;

        if (!g_uds_postevent_saved_valid) {
            memcpy(g_uds_postevent_saved, (const void *)target,
                   sizeof g_uds_postevent_saved);
            g_uds_postevent_saved_valid = 1;
            logf("V50 hook saved PostEvent prologue target=%p len=%u",
                 (void *)target, (unsigned)sizeof g_uds_postevent_saved);
        }

        memset(patch, 0x90, sizeof patch);
        patch[0] = 0x48;
        patch[1] = 0xb8;
        memcpy(&patch[2], &hook, sizeof hook);
        patch[10] = 0xff;
        patch[11] = 0xe0;

        memcpy((void *)target, patch, sizeof patch);

        rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                             PROT_READ | PROT_EXEC);
        logf("V50 hook install restore RX -> 0x%08x", rc);
        g_uds_postevent_hook_installed = 1;
        return rc;
    }

    if (!g_uds_postevent_hook_installed)
        return 0;
    if (!g_uds_postevent_saved_valid)
        return -1;

    rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC);
    logf("V50 hook remove mprotect RWX page=%p -> 0x%08x",
         (void *)page, rc);
    if (rc < 0)
        return rc;

    memcpy((void *)target, g_uds_postevent_saved,
           sizeof g_uds_postevent_saved);

    rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                         PROT_READ | PROT_EXEC);
    logf("V50 hook remove restore RX -> 0x%08x", rc);
    g_uds_postevent_hook_installed = 0;
    return rc;
}

static int
patch_uds_function_hook(uintptr_t target,
                        uintptr_t hook,
                        uint8_t *saved,
                        int *saved_valid,
                        volatile int *installed,
                        int install,
                        const char *tag)
{
    uint8_t patch[UDS_HOOK_PATCH_LEN];
    uintptr_t page;
    int rc;

    if (target == 0)
        return -1;

    page = target & ~(uintptr_t)(UDS_HOOK_PAGE_SIZE - 1);

    if (install) {
        if (*installed)
            return 0;

        logf("V63 hook %s prepare target=%p page=%p hook=%p",
             tag, (void *)target, (void *)page, (void *)hook);

        rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                             PROT_READ | PROT_WRITE | PROT_EXEC);
        logf("V64 hook install %s mprotect before save page=%p -> 0x%08x",
             tag, (void *)page, rc);
        if (rc < 0)
            return rc;

        if (!*saved_valid) {
            memcpy(saved, (const void *)target, UDS_HOOK_PATCH_LEN);
            *saved_valid = 1;
            logf("V61 hook saved %s prologue target=%p len=%u",
                 tag, (void *)target, (unsigned)UDS_HOOK_PATCH_LEN);
        }

        memset(patch, 0x90, sizeof patch);
        patch[0] = 0x48;
        patch[1] = 0xb8;
        memcpy(&patch[2], &hook, sizeof hook);
        patch[10] = 0xff;
        patch[11] = 0xe0;

        memcpy((void *)target, patch, sizeof patch);

        rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                             PROT_READ | PROT_EXEC);
        logf("V61 hook install %s restore RX -> 0x%08x", tag, rc);
        *installed = 1;
        return rc;
    }

    if (!*installed)
        return 0;
    if (!*saved_valid)
        return -1;

    rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                         PROT_READ | PROT_WRITE | PROT_EXEC);
    logf("V61 hook remove %s mprotect RWX page=%p -> 0x%08x",
         tag, (void *)page, rc);
    if (rc < 0)
        return rc;

    memcpy((void *)target, saved, UDS_HOOK_PATCH_LEN);

    rc = kernel_mprotect(-1, (unsigned long)page, UDS_HOOK_PAGE_SIZE,
                         PROT_READ | PROT_EXEC);
    logf("V61 hook remove %s restore RX -> 0x%08x", tag, rc);
    *installed = 0;
    return rc;
}

static int
patch_uds_createevent_hook(int install)
{
    return patch_uds_function_hook((uintptr_t)p_UdsCreateEvent,
                                   (uintptr_t)hooked_uds_create_event,
                                   g_uds_createevent_saved,
                                   &g_uds_createevent_saved_valid,
                                   &g_uds_createevent_hook_installed,
                                   install,
                                   "CreateEvent");
}

static int
patch_uds_setint32_hook(int install)
{
    return patch_uds_function_hook((uintptr_t)p_UdsPropSetInt32,
                                   (uintptr_t)hooked_uds_set_int32,
                                   g_uds_setint32_saved,
                                   &g_uds_setint32_saved_valid,
                                   &g_uds_setint32_hook_installed,
                                   install,
                                   "SetInt32");
}

static int
post_unlock_trophy_event_live(SceNpUniversalDataSystemContext context,
                              SceNpUniversalDataSystemHandle handle,
                              int trophy_id)
{
    SceNpUniversalDataSystemEvent *event = NULL;
    SceNpUniversalDataSystemEventPropertyObject *prop = NULL;
    int rc;
    int ret;

    rc = p_UdsCreateEvent("_UnlockTrophy", NULL, &event, &prop);
    logf("V50 live CreateEvent(_UnlockTrophy id=%d) -> 0x%08x event=%p prop=%p",
         trophy_id, rc, event, prop);
    if (rc < 0)
        return rc;

    rc = p_UdsPropSetInt32(prop, "_trophy_id", trophy_id);
    logf("V50 live SetInt32(_trophy_id=%d) -> 0x%08x", trophy_id, rc);
    if (rc < 0) {
        ret = rc;
        goto out;
    }

    rc = p_UdsPostEvent(context, handle, event,
                        SCE_NP_UNIVERSAL_DATA_SYSTEM_POST_EVENT_OPTION_GENERATED_BY_CODEGEN);
    logf("V50 live PostEvent(_UnlockTrophy id=%d, opt=codegen) -> 0x%08x",
         trophy_id, rc);
    ret = rc;

    if (rc < 0) {
        int rc_plain = p_UdsPostEvent(context, handle, event, 0);
        logf("V50 live PostEvent(_UnlockTrophy id=%d, opt=0) -> 0x%08x",
             trophy_id, rc_plain);
        if (rc_plain >= 0)
            ret = rc_plain;
    }

out:
    if (event != NULL) {
        rc = p_UdsDestroyEvent(event);
        logf("V50 live DestroyEvent(id=%d) -> 0x%08x", trophy_id, rc);
    }
    return ret;
}

static void
post_trophy_range_live(SceNpUniversalDataSystemContext context,
                       SceNpUniversalDataSystemHandle handle,
                       int lo,
                       int hi)
{
    int ok = 0;
    int errors = 0;
    int start = lo;

    if (lo < 0)
        lo = 0;
    if (hi < lo)
        hi = lo;

    start = lo;
    if (lo == 0 && hi > 0)
        start = 1;

    logf("V50 live post range begin ctx=%d handle=%d range=%d..%d order_start=%d",
         context, handle, lo, hi, start);

    for (int id = start; id <= hi; id++) {
        int rc = post_unlock_trophy_event_live(context, handle, id);
        if (rc < 0)
            errors++;
        else
            ok++;
        sceKernelUsleep(200000);
    }

    if (lo == 0) {
        int rc = post_unlock_trophy_event_live(context, handle, 0);
        if (rc < 0)
            errors++;
        else
            ok++;
    }

    g_uds_postevent_hook_post_ok = ok;
    g_uds_postevent_hook_post_errors = errors;
    logf("V50 live post range done ok=%d errors=%d", ok, errors);
}

static void __attribute__((unused))
post_all_goat_trophies_live(SceNpUniversalDataSystemContext context,
                            SceNpUniversalDataSystemHandle handle)
{
    post_trophy_range_live(context, handle,
                           GOAT_TROPHY_MIN_ID, GOAT_TROPHY_MAX_ID);
}

static int
hooked_uds_create_event(const char *name,
                        const SceNpUniversalDataSystemEventPropertyObject *initial_prop,
                        SceNpUniversalDataSystemEvent **event_out,
                        SceNpUniversalDataSystemEventPropertyObject **prop_out)
{
    int rc;
    SceNpUniversalDataSystemEvent *created_event = NULL;
    SceNpUniversalDataSystemEventPropertyObject *created_prop = NULL;

    if (g_uds_createevent_hook_busy)
        return p_UdsCreateEvent(name, initial_prop, event_out, prop_out);

    g_uds_createevent_hook_busy = 1;
    logf("V61 trace CreateEvent enter name='%s' initial=%p out_event=%p out_prop=%p",
         name != NULL ? name : "<null>", initial_prop, event_out, prop_out);

    (void)patch_uds_createevent_hook(0);
    rc = p_UdsCreateEvent(name, initial_prop, event_out, prop_out);

    if (event_out != NULL)
        created_event = *event_out;
    if (prop_out != NULL)
        created_prop = *prop_out;

    uds_trace_store(created_event, created_prop, name);
    logf("V61 trace CreateEvent exit name='%s' -> 0x%08x event=%p prop=%p",
         name != NULL ? name : "<null>", rc, created_event, created_prop);

    (void)patch_uds_createevent_hook(1);
    g_uds_createevent_hook_busy = 0;
    return rc;
}

static int
hooked_uds_set_int32(SceNpUniversalDataSystemEventPropertyObject *prop,
                     const char *key,
                     int32_t value)
{
    int rc;
    const char *event_name;

    if (g_uds_setint32_hook_busy)
        return p_UdsPropSetInt32(prop, key, value);

    g_uds_setint32_hook_busy = 1;
    event_name = uds_trace_name_for_prop(prop);
    logf("V61 trace SetInt32 enter event='%s' prop=%p key='%s' value=%d",
         event_name, prop, key != NULL ? key : "<null>", value);

    (void)patch_uds_setint32_hook(0);
    rc = p_UdsPropSetInt32(prop, key, value);
    logf("V61 trace SetInt32 exit event='%s' key='%s' value=%d -> 0x%08x",
         event_name, key != NULL ? key : "<null>", value, rc);

    (void)patch_uds_setint32_hook(1);
    g_uds_setint32_hook_busy = 0;
    return rc;
}

static int
hooked_uds_post_event(SceNpUniversalDataSystemContext context,
                      SceNpUniversalDataSystemHandle handle,
                      const SceNpUniversalDataSystemEvent *event,
                      uint64_t options)
{
    int rc;
    int call_no;
    const char *event_name;

    if (g_uds_postevent_hook_busy)
        return p_UdsPostEvent(context, handle, event, options);

    g_uds_postevent_hook_busy = 1;
    call_no = ++g_uds_postevent_hook_calls;
    g_uds_live_context = context;
    g_uds_live_handle = handle;

    (void)patch_uds_postevent_hook(0);
    event_name = uds_trace_name_for_event(event);

    if (call_no <= 16 || (call_no % 50) == 0) {
        logf("V61 trace PostEvent call=%d event='%s' ctx=%d handle=%d event_ptr=%p opt=0x%llx",
             call_no, event_name, context, handle, event,
             (unsigned long long)options);
        log_uds_event_bytes("V61 trace PostEvent", event);
    }

    rc = p_UdsPostEvent(context, handle, event, options);
    logf("V61 trace PostEvent original call=%d event='%s' -> 0x%08x",
         call_no, event_name, rc);

#if !ENABLE_UDS_POSTEVENT_TRACE_ONLY
    if (!g_uds_postevent_hook_posted_all &&
        context != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT &&
        handle != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE) {
        g_uds_postevent_hook_posted_all = 1;
        logf("V50 hook captured live ctx/handle; posting selected trophies now range=%d..%d",
             g_live_post_lo, g_live_post_hi);
        post_trophy_range_live(context, handle,
                               g_live_post_lo, g_live_post_hi);
    }
#endif

    (void)patch_uds_postevent_hook(1);
    g_uds_postevent_hook_busy = 0;
    return rc;
}

static int
run_uds_postevent_hook_monitor(int seconds, int argc, char *argv[])
{
    uint32_t num_trophies = 0;
    int lo = DEFAULT_TROPHY_ID;
    int hi = DEFAULT_TROPHY_ID;
    int rc;

    if (p_UdsPostEvent == NULL || p_UdsCreateEvent == NULL ||
        p_UdsPropSetInt32 == NULL || p_UdsDestroyEvent == NULL) {
        logf("V50 hook missing UDS symbols post=%p create=%p set=%p destroy=%p",
             p_UdsPostEvent, p_UdsCreateEvent, p_UdsPropSetInt32,
             p_UdsDestroyEvent);
        notify("trophy_unlocker: V50 symboles UDS manquants");
        return -1;
    }

    if (ENABLE_TROPHY2_CONTEXT_SCAN)
        (void)scan_existing_trophy2_contexts(&num_trophies);
    num_trophies = ensure_trophy_count(num_trophies, "hook-monitor");
    if (select_unlock_range(argc, argv, num_trophies, &lo, &hi) != 0)
        return -1;
    g_live_post_lo = lo;
    g_live_post_hi = hi;

    g_uds_postevent_hook_calls = 0;
    g_uds_postevent_hook_posted_all = 0;
    g_uds_postevent_hook_post_ok = 0;
    g_uds_postevent_hook_post_errors = 0;
    g_uds_live_context = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    g_uds_live_handle = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;
    uds_trace_reset();

    if (ENABLE_UDS_POSTEVENT_TRACE_ONLY) {
        rc = patch_uds_createevent_hook(1);
        logf("V61 trace hook CreateEvent install -> 0x%08x", rc);
        if (rc < 0)
            return rc;

        rc = patch_uds_setint32_hook(1);
        logf("V61 trace hook SetInt32 install -> 0x%08x", rc);
        if (rc < 0) {
            (void)patch_uds_createevent_hook(0);
            return rc;
        }
    }

    rc = patch_uds_postevent_hook(1);
    logf("V61 trace hook PostEvent install -> 0x%08x", rc);
    notify("trophy_unlocker: V61 trace UDS rc=0x%08x ids=%d..%d",
           rc, g_live_post_lo, g_live_post_hi);
    if (rc < 0) {
        if (ENABLE_UDS_POSTEVENT_TRACE_ONLY) {
            (void)patch_uds_setint32_hook(0);
            (void)patch_uds_createevent_hook(0);
        }
        return rc;
    }

    for (int i = 0; i < seconds * 10; i++) {
        if (!ENABLE_UDS_POSTEVENT_TRACE_ONLY &&
            g_uds_postevent_hook_posted_all)
            break;
        if (p_NpCheckCallback != NULL)
            (void)p_NpCheckCallback();
        sceKernelUsleep(100000);
    }

    if (g_uds_postevent_hook_installed)
        (void)patch_uds_postevent_hook(0);
    if (g_uds_setint32_hook_installed)
        (void)patch_uds_setint32_hook(0);
    if (g_uds_createevent_hook_installed)
        (void)patch_uds_createevent_hook(0);

    logf("V61 trace hook monitor done calls=%d posted_all=%d ok=%d errors=%d live_ctx=%d live_handle=%d trace_only=%d",
         g_uds_postevent_hook_calls, g_uds_postevent_hook_posted_all,
         g_uds_postevent_hook_post_ok, g_uds_postevent_hook_post_errors,
         g_uds_live_context, g_uds_live_handle,
         ENABLE_UDS_POSTEVENT_TRACE_ONLY);
    notify("trophy_unlocker: V61 trace done calls=%d ok=%d err=%d",
           g_uds_postevent_hook_calls, g_uds_postevent_hook_post_ok,
           g_uds_postevent_hook_post_errors);

    if (ENABLE_UDS_POSTEVENT_TRACE_ONLY)
        return 0;
    return g_uds_postevent_hook_posted_all ? 0 : -2;
}

static int
read_live_uds_context_file(SceNpUniversalDataSystemContext *context,
                           SceNpUniversalDataSystemHandle *handle)
{
    char buf[128];
    char *p;
    char *endp;
    unsigned long ctx_value;
    unsigned long handle_value;
    int fd;
    int n;

    *context = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    *handle = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;

    fd = open(UDS_LIVE_CONTEXT_FILE, O_RDONLY, 0);
    if (fd < 0) {
        logf("V51 live ctx file missing: %s", UDS_LIVE_CONTEXT_FILE);
        return -1;
    }

    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) {
        logf("V51 live ctx file read failed n=%d", n);
        return -1;
    }
    buf[n] = '\0';

    p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
        p++;

    ctx_value = strtoul(p, &endp, 0);
    if (endp == p)
        return -1;

    p = endp;
    while (*p == ' ' || *p == '\t' || *p == ',' ||
           *p == '\r' || *p == '\n')
        p++;

    handle_value = strtoul(p, &endp, 0);
    if (endp == p)
        return -1;

    *context = (SceNpUniversalDataSystemContext)(int32_t)ctx_value;
    *handle = (SceNpUniversalDataSystemHandle)(int32_t)handle_value;
    logf("V51 live ctx file parsed ctx=0x%08lx(%d) handle=0x%08lx(%d)",
         ctx_value, *context, handle_value, *handle);
    return 0;
}

static int
run_live_context_unlock_from_file(int argc, char *argv[])
{
    SceNpUniversalDataSystemContext live_ctx;
    SceNpUniversalDataSystemHandle live_handle;
    uint32_t num_trophies = 0;
    int lo = DEFAULT_TROPHY_ID;
    int hi = DEFAULT_TROPHY_ID;

    if (read_live_uds_context_file(&live_ctx, &live_handle) != 0) {
        notify("trophy_unlocker: V51 ctx fichier absent/invalide");
        return -1;
    }

    if (live_ctx == SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT ||
        live_handle == SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE) {
        notify("trophy_unlocker: V51 ctx/handle invalide");
        return -1;
    }

    notify("trophy_unlocker: V51 live ctx=%d handle=%d",
           live_ctx, live_handle);

    if (ENABLE_TROPHY2_CONTEXT_SCAN)
        (void)scan_existing_trophy2_contexts(&num_trophies);
    num_trophies = ensure_trophy_count(num_trophies, "live-context");
    if (select_unlock_range(argc, argv, num_trophies, &lo, &hi) != 0)
        return -1;

    post_trophy_range_live(live_ctx, live_handle, lo, hi);
    sceKernelUsleep(POST_UNLOCK_SETTLE_USEC);
    pump_np_callbacks("after-live-file-posts", POST_UNLOCK_FINAL_PUMP_COUNT);
    run_trophy2_post_info_diag(SCE_NP_TROPHY2_INVALID_CONTEXT,
                               SCE_NP_TROPHY2_INVALID_HANDLE,
                               lo, hi, "after-live-file");
    notify("trophy_unlocker: V51 done ok=%d err=%d",
           g_uds_postevent_hook_post_ok,
           g_uds_postevent_hook_post_errors);

    return g_uds_postevent_hook_post_errors == 0 ? 0 : -1;
}

static void
try_existing_uds_contexts(int lo, int hi,
                          SceNpUniversalDataSystemContext created_ctx,
                          int *posted)
{
    int start = UDS_CONTEXT_SCAN_BASE;
    int end = start + UDS_CONTEXT_SCAN_LIMIT - 1;
    int invalid_contexts = 0;
    int not_registered = 0;
    int invalid_args = 0;
    int other_errors = 0;

    logf("V28 scan existing UDS contexts 0x%08x..0x%08x skip=0x%08x ids=%d..%d",
         start, end, (int)created_ctx, lo, hi);
    notify("trophy_unlocker: V28 scan contextes UDS existants");

    for (int ctx = start; ctx <= end; ctx++) {
        if (ctx == (int)created_ctx)
            continue;

        for (int id = lo; id <= hi; id++) {
            int rc = post_unlock_trophy_event((SceNpUniversalDataSystemContext)ctx, id);
            logf("V28 scan PostEvent ctx=0x%08x id=%d -> 0x%08x", ctx, id, rc);
            if (rc >= 0) {
                g_last_accepted_uds_context =
                    (SceNpUniversalDataSystemContext)ctx;
                (*posted)++;
                notify("trophy_unlocker: V28 posted ctx=0x%08x id=%d", ctx, id);
                return;
            }

            switch ((uint32_t)rc) {
            case 0x80553104U:
                invalid_contexts++;
                break;
            case 0x80553120U:
                not_registered++;
                break;
            case UDS_ERROR_INVALID_ARGUMENT_RC:
                invalid_args++;
                break;
            default:
                other_errors++;
                break;
            }
            sceKernelUsleep(10000);
        }
    }

    logf("V28 scan existing UDS contexts: no accepted context invalid=%d not_registered=%d invalid_arg=%d other=%d",
         invalid_contexts, not_registered, invalid_args, other_errors);
    notify("trophy_unlocker: V28 aucun contexte UDS accepte");
}

static int
select_uds_probe_trophy_id(int lo, int hi)
{
    for (int id = lo; id <= hi && id < TROPHY_UNLOCKER_MAX_ALL; id++) {
        if (id >= 0 && g_seen_trophy_valid[id] && g_seen_trophy_unlocked[id])
            return id;
    }

    for (int id = 0; id < TROPHY_UNLOCKER_MAX_ALL; id++) {
        if (g_seen_trophy_valid[id] && g_seen_trophy_unlocked[id])
            return id;
    }

    return lo >= 0 ? lo : 0;
}

static int
find_existing_uds_context_with_probe(int probe_id,
                                     SceNpUniversalDataSystemContext skip_ctx,
                                     SceNpUniversalDataSystemContext *found_ctx)
{
    int start = UDS_CONTEXT_SCAN_BASE;
    int end = start + UDS_CONTEXT_SCAN_LIMIT - 1;

    *found_ctx = SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    logf("V60 find existing UDS ctx probe_id=%d range=0x%08x..0x%08x skip=0x%08x",
         probe_id, start, end, (int)skip_ctx);
    notify("trophy_unlocker: V60 cherche ctx UDS id=%d", probe_id);

    for (int ctx = start; ctx <= end; ctx++) {
        int rc;

        if (ctx == (int)skip_ctx)
            continue;

        rc = post_unlock_trophy_event((SceNpUniversalDataSystemContext)ctx,
                                      probe_id);
        logf("V60 probe PostEvent ctx=0x%08x id=%d -> 0x%08x",
             ctx, probe_id, rc);
        if (rc >= 0) {
            *found_ctx = (SceNpUniversalDataSystemContext)ctx;
            g_last_accepted_uds_context =
                (SceNpUniversalDataSystemContext)ctx;
            notify("trophy_unlocker: V60 ctx UDS OK 0x%08x", ctx);
            return 0;
        }

        sceKernelUsleep(10000);
    }

    notify("trophy_unlocker: V60 aucun ctx UDS actif");
    return -1;
}

static int
post_trophy_range_on_existing_uds_context(SceNpUniversalDataSystemContext ctx,
                                          int lo,
                                          int hi)
{
    int posted = 0;
    int errors = 0;
    int start;

    if (lo < 0)
        lo = 0;
    if (hi < lo)
        hi = lo;

    start = lo;
    if (lo == 0 && hi > 0)
        start = 1;

    logf("V60 post all on existing UDS ctx=0x%08x range=%d..%d start=%d",
         (int)ctx, lo, hi, start);
    notify("trophy_unlocker: V60 post all %d..%d", lo, hi);

    for (int id = start; id <= hi; id++) {
        int rc;

        if (id < TROPHY_UNLOCKER_MAX_ALL &&
            g_seen_trophy_valid[id] && g_seen_trophy_unlocked[id]) {
            logf("V60 skip already unlocked id=%d", id);
            continue;
        }

        rc = post_unlock_trophy_event(ctx, id);
        logf("V60 post existing ctx id=%d -> 0x%08x", id, rc);
        if (rc >= 0) {
            posted++;
            pump_np_callbacks("after-v60-existing-post", 2);
        } else {
            errors++;
        }
        sceKernelUsleep(200000);
    }

    if (lo == 0) {
        int id = 0;
        int rc;

        if (!(id < TROPHY_UNLOCKER_MAX_ALL &&
              g_seen_trophy_valid[id] && g_seen_trophy_unlocked[id])) {
            rc = post_unlock_trophy_event(ctx, id);
            logf("V60 post existing ctx platinum id=0 -> 0x%08x", rc);
            if (rc >= 0)
                posted++;
            else
                errors++;
        } else {
            logf("V60 skip already unlocked platinum id=0");
        }
    }

    sceKernelUsleep(POST_UNLOCK_SETTLE_USEC);
    pump_np_callbacks("after-v60-existing-all", POST_UNLOCK_FINAL_PUMP_COUNT);
    notify("trophy_unlocker: V60 existing ctx posted=%d err=%d",
           posted, errors);
    return errors ? -1 : posted;
}

static int
dl_resolve_all(void)
{
    int rc;
    static const struct { const char *path; const char *tag; } paths[] = {
        { "libSceNpTrophy.sprx",                       "bare"    },
        { "/system_ex/common_ex/lib/libSceNpTrophy.sprx","common_ex" },
        { "/system_ex/priv_ex/lib/libSceNpTrophy.sprx","priv_ex" },
        { "/system/priv/lib/libSceNpTrophy.sprx",      "priv"    },
        { "/app0/sce_module/libSceNpTrophy.sprx",      "app0"    },
        { NULL, NULL }
    };

    static const struct { const char *path; const char *tag; } system_common_probe[] = {
        { "/system/common/lib/libSceNpTrophy.sprx",     "sys_common_trophy" },
        { "/system/common/lib/libSceNpTrophy2.sprx",    "sys_common_trophy2" },
        { "/system/common/lib/libSceNpTrophyCore.sprx", "sys_common_core" },
        { NULL, NULL }
    };

    for (int i = 0; paths[i].path; i++)
        probe_file_path(paths[i].path, paths[i].tag);
    for (int i = 0; system_common_probe[i].path; i++)
        probe_file_path(system_common_probe[i].path, system_common_probe[i].tag);

    int self_pid = getpid();

    notify("DEBUG V21: current pid=%d", self_pid);
    log_process_info_for_pid(self_pid);
    log_process_info_for_pid(56);
    log_process_info_for_pid(57);

    notify("DEBUG V22: PS5 Trophy2/UDS injected mode");
    probe_trophy_dynlibs_for_pid(self_pid, "self-v22");
    probe_trophy_dynlibs_for_pid(56, "pid56-known");
    probe_trophy_dynlibs_for_pid(57, "pid57-known");

    if (ENABLE_REMOTE_VSH_SYMBOL_PROBE) {
        notify("trophy_unlocker: V54 probe symboles VSH");
        probe_vsh_system_symbols_for_pid(56);
        probe_vsh_system_symbols_for_pid(57);
    }

    if (resolve_ps5_trophy2_uds_symbols() != 0)
        return -1;

    notify("DEBUG V22: resolve done, entering unlock path");
    return 0;

    for (int i = 0; paths[i].path; i++) {
        logf("LoadStartModule(%s) ...", paths[i].path);
        notify("DEBUG V14: before LoadStart %s", paths[i].tag);
        rc = sceKernelLoadStartModule(paths[i].path, 0, NULL, 0, NULL, NULL);
        logf("LoadStartModule(%s) -> 0x%08x", paths[i].tag, rc);
        notify("DEBUG V14: after LoadStart %s rc=0x%08x", paths[i].tag, rc);
        if (rc >= 0) { trophy_h = rc; break; }
    }

    if (trophy_h < 0) {
        int rc22;
        int rc20;

        logf("trying sceSysmoduleLoadModuleInternal(0x80000022) ...");
        notify("DEBUG V14: before sysmod22");
        rc22 = sceSysmoduleLoadModuleInternal(0x80000022);
        logf("sysmodInt(0x80000022) -> 0x%08x", rc22);
        notify("DEBUG V14: after sysmod22 rc=0x%08x", rc22);

        logf("trying sceSysmoduleLoadModuleInternal(0x80000020) ...");
        notify("DEBUG V14: before sysmod20");
        rc20 = sceSysmoduleLoadModuleInternal(0x80000020);
        logf("sysmodInt(0x80000020) -> 0x%08x", rc20);
        notify("DEBUG V14: after sysmod20 rc=0x%08x", rc20);

        for (int i = 0; paths[i].path; i++) {
            logf("post-sysmod LoadStartModule(%s) ...", paths[i].path);
            notify("DEBUG V14: post LoadStart %s", paths[i].tag);
            rc = sceKernelLoadStartModule(paths[i].path, 0, NULL, 0, NULL, NULL);
            logf("post-sysmod LoadStartModule(%s) -> 0x%08x", paths[i].tag, rc);
            notify("DEBUG V14: post LoadStart %s rc=0x%08x", paths[i].tag, rc);
            if (rc >= 0) { trophy_h = rc; break; }
        }

        if (trophy_h < 0) {
            uint32_t kh = 0;
            int kr;

            notify("DEBUG V15: before kernel_dynlib_handle");
            kr = kernel_dynlib_handle(getpid(), "libSceNpTrophy.sprx", &kh);
            logf("kernel_dynlib_handle(libSceNpTrophy.sprx) -> 0x%08x handle=0x%08x",
                 kr, kh);
            notify("DEBUG V15: kernel_dynlib_handle rc=0x%08x h=0x%08x", kr, kh);
            if (kr == 0 && kh != 0) {
                trophy_kh = kh;
                trophy_use_kernel_dynlib = 1;
            }
        }

        if (trophy_h < 0 && !trophy_use_kernel_dynlib) {
            uint32_t kh = 0;
            int sr;
            int kr;

            notify("DEBUG V18: skip UDS 0x0105 because V17 hung there");

            notify("DEBUG V18: before sysmodule Trophy2 0x0110");
            sr = sceSysmoduleLoadModule(SCE_SYSMODULE_NP_TROPHY2);
            logf("sceSysmoduleLoadModule(Trophy2 0x0110) -> 0x%08x", sr);
            notify("DEBUG V18: sysmodule Trophy2 rc=0x%08x", sr);

            kr = kernel_dynlib_handle(getpid(), "libSceNpTrophy2.sprx", &kh);
            logf("kernel_dynlib_handle(libSceNpTrophy2.sprx) -> 0x%08x handle=0x%08x",
                 kr, kh);
            notify("DEBUG V18: kh Trophy2 rc=0x%08x h=0x%08x", kr, kh);
        }

        if (trophy_h < 0 && !trophy_use_kernel_dynlib) {
            notify("DEBUG V18: skip pid scan after sysmodule test");
        }
    }

    if (trophy_h < 0 && !trophy_use_kernel_dynlib) {
        notify("DEBUG V18: FINAL module FAILED");
        return -1;
    }
    if (trophy_use_kernel_dynlib)
        notify("DEBUG V18: FINAL module OK kernel h=0x%08x", trophy_kh);
    else
        notify("DEBUG V18: FINAL module OK h=%d", trophy_h);

    struct { const char *name; void **slot; int optional; } syms[] = {
        { "sceNpTrophyCreateContext",      (void **)&p_CreateContext,   0 },
        { "sceNpTrophyDestroyContext",     (void **)&p_DestroyContext,  0 },
        { "sceNpTrophyCreateHandle",       (void **)&p_CreateHandle,    0 },
        { "sceNpTrophyDestroyHandle",      (void **)&p_DestroyHandle,   0 },
        { "sceNpTrophyRegisterContext",    (void **)&p_RegisterContext, 0 },
        { "sceNpTrophyGetGameInfo",        (void **)&p_GetGameInfo,     0 },
        { "sceNpTrophyUnlockTrophy",       (void **)&p_UnlockTrophy,    0 },
        { "sceNpTrophyIntGetRunningTitle", (void **)&p_GetRunning,      1 },
    };
    for (size_t i = 0; i < sizeof(syms)/sizeof(syms[0]); i++) {
        notify("DEBUG V14: before dlsym %.40s", syms[i].name);
        int r = resolve_trophy_symbol(syms[i].name, syms[i].slot);
        logf("dlsym(%s) -> 0x%08x ptr=%p", syms[i].name, r, *syms[i].slot);
        if ((r < 0 || *syms[i].slot == NULL) && !syms[i].optional) {
            notify("trophy_unlocker: dlsym(%s) FAILED", syms[i].name);
            return -1;
        }
    }
    notify("trophy_unlocker: all symbols resolved");
    return 0;
}

/* ---------------------------------------------------------------- helpers */

static int __attribute__((unused))
parse_npcommid(const char *s, SceNpCommunicationId *out)
{
    memset(out, 0, sizeof *out);
    size_t n = strlen(s);
    if (n < 9 || n > 12) return -1;
    memcpy(out->data, s, 9);
    out->term = '\0';
    out->num  = 0;
    if (n >= 12) {
        char a = s[10], b = s[11];
        if (a < '0' || a > '9' || b < '0' || b > '9') return -1;
        out->num = (uint8_t)((a - '0') * 10 + (b - '0'));
    }
    return 0;
}

static int
resolve_ps4_trophy1_symbols(void)
{
    int rc;
    uint32_t kh = 0;
    static const struct { const char *path; const char *tag; } paths[] = {
        { "libSceNpTrophy.sprx",                        "bare" },
        { "/system/common/lib/libSceNpTrophy.sprx",     "sys_common" },
        { "/system_ex/common_ex/lib/libSceNpTrophy.sprx","common_ex" },
        { "/system_ex/priv_ex/lib/libSceNpTrophy.sprx", "priv_ex" },
        { "/system/priv/lib/libSceNpTrophy.sprx",       "priv" },
        { "/app0/sce_module/libSceNpTrophy.sprx",       "app0" },
        { NULL, NULL }
    };

    trophy_h = -1;
    trophy_kh = 0;
    trophy_use_kernel_dynlib = 0;

    notify("trophy_unlocker: V73 mode PS4 Trophy1");
    log_process_info_for_pid(getpid());
    probe_trophy_dynlibs_for_pid(getpid(), "self-v73-ps4");

    rc = kernel_dynlib_handle(getpid(), "libSceNpTrophy.sprx", &kh);
    logf("V73 kernel_dynlib_handle(libSceNpTrophy.sprx) -> 0x%08x h=0x%08x",
         rc, kh);
    if (rc == 0 && kh != 0) {
        trophy_kh = kh;
        trophy_use_kernel_dynlib = 1;
        notify("trophy_unlocker: V73 Trophy1 deja charge h=0x%08x", kh);
    }

    for (int i = 0; !trophy_use_kernel_dynlib && paths[i].path != NULL; i++) {
        probe_file_path(paths[i].path, paths[i].tag);
        logf("V73 LoadStartModule(%s) ...", paths[i].path);
        rc = sceKernelLoadStartModule(paths[i].path, 0, NULL, 0, NULL, NULL);
        logf("V73 LoadStartModule(%s) -> 0x%08x", paths[i].tag, rc);
        if (rc >= 0) {
            trophy_h = rc;
            break;
        }
    }

    if (trophy_h < 0 && !trophy_use_kernel_dynlib) {
        int rc22;
        int rc20;

        rc22 = sceSysmoduleLoadModuleInternal(0x80000022);
        logf("V73 sysmodule internal 0x80000022 -> 0x%08x", rc22);
        rc20 = sceSysmoduleLoadModuleInternal(0x80000020);
        logf("V73 sysmodule internal 0x80000020 -> 0x%08x", rc20);

        rc = kernel_dynlib_handle(getpid(), "libSceNpTrophy.sprx", &kh);
        logf("V73 post-sysmodule kernel_dynlib_handle -> 0x%08x h=0x%08x",
             rc, kh);
        if (rc == 0 && kh != 0) {
            trophy_kh = kh;
            trophy_use_kernel_dynlib = 1;
        }
    }

    if (trophy_h < 0 && !trophy_use_kernel_dynlib) {
        notify("trophy_unlocker: V73 libSceNpTrophy introuvable");
        return -1;
    }

    struct { const char *name; void **slot; int optional; } syms[] = {
        { "sceNpTrophyCreateContext",      (void **)&p_CreateContext,   0 },
        { "sceNpTrophyDestroyContext",     (void **)&p_DestroyContext,  0 },
        { "sceNpTrophyCreateHandle",       (void **)&p_CreateHandle,    0 },
        { "sceNpTrophyDestroyHandle",      (void **)&p_DestroyHandle,   0 },
        { "sceNpTrophyRegisterContext",    (void **)&p_RegisterContext, 0 },
        { "sceNpTrophyGetGameInfo",        (void **)&p_GetGameInfo,     0 },
        { "sceNpTrophyUnlockTrophy",       (void **)&p_UnlockTrophy,    0 },
        { "sceNpTrophyIntGetRunningTitle", (void **)&p_GetRunning,      1 },
    };

    for (size_t i = 0; i < sizeof(syms) / sizeof(syms[0]); i++) {
        int r = resolve_trophy_symbol(syms[i].name, syms[i].slot);
        logf("V73 dlsym(%s) -> 0x%08x ptr=%p",
             syms[i].name, r, *syms[i].slot);
        if ((r < 0 || *syms[i].slot == NULL) && !syms[i].optional) {
            notify("trophy_unlocker: V73 dlsym %s FAILED", syms[i].name);
            return -1;
        }
    }

    if (resolve_self_symbol("libSceUserService.sprx",
                            "sceUserServiceGetInitialUser",
                            (void **)&p_UserServiceGetInitialUser) != 0 ||
        p_UserServiceGetInitialUser == NULL) {
        notify("trophy_unlocker: V76 user service introuvable");
        return -1;
    }
    logf("V76 dlsym(sceUserServiceGetInitialUser) -> %p",
         p_UserServiceGetInitialUser);

    notify("trophy_unlocker: V73 symboles PS4 OK");
    return 0;
}

static int
detect_ps4_npcomm(SceNpCommunicationId *comm_id)
{
    char npcomm[13];
    int rc;

    memset(comm_id, 0, sizeof *comm_id);

    if (p_GetRunning != NULL) {
        rc = p_GetRunning(0, comm_id);
        logf("V73 IntGetRunningTitle -> 0x%08x data=%.9s num=%u",
             rc, comm_id->data, comm_id->num);
        if (rc == 0 && comm_id->data[0] != '\0') {
            notify("trophy_unlocker: V73 running %.9s_%02u",
                   comm_id->data, comm_id->num);
            return 0;
        }
    } else {
        logf("V73 IntGetRunningTitle unavailable");
    }

    if (detect_npcomm_for_current_app(npcomm, sizeof npcomm) == 0 &&
        parse_npcommid(npcomm, comm_id) == 0) {
        notify("trophy_unlocker: V73 NPWR override %.9s_%02u",
               comm_id->data, comm_id->num);
        return 0;
    }

    notify("trophy_unlocker: V73 NPWR PS4 introuvable");
    return -1;
}

static int
read_ps4_signature_candidates(SceNpCommunicationSignature *sigs, int max_sigs)
{
    int fd;
    int n;
    int count;

    if (sigs == NULL || max_sigs <= 0)
        return 0;

    fd = open(TROPHY_UNLOCKER_NPSIG_FILE, O_RDONLY, 0);
    if (fd < 0) {
        logf("V75 npsig open(%s) -> %d", TROPHY_UNLOCKER_NPSIG_FILE, fd);
        return 0;
    }

    n = read(fd, g_ucp_scan_buf, sizeof g_ucp_scan_buf);
    close(fd);
    logf("V75 npsig read(%s) -> %d", TROPHY_UNLOCKER_NPSIG_FILE, n);
    if (n < (int)sizeof(SceNpCommunicationSignature))
        return 0;

    count = n / (int)sizeof(SceNpCommunicationSignature);
    if (count > max_sigs)
        count = max_sigs;

    for (int i = 0; i < count; i++) {
        memcpy(&sigs[i],
               &g_ucp_scan_buf[i * (int)sizeof(SceNpCommunicationSignature)],
               sizeof(SceNpCommunicationSignature));
        logf("V75 npsig[%d] first=%02x%02x%02x%02x last=%02x%02x%02x%02x",
             i,
             sigs[i].data[0], sigs[i].data[1],
             sigs[i].data[2], sigs[i].data[3],
             sigs[i].data[156], sigs[i].data[157],
             sigs[i].data[158], sigs[i].data[159]);
    }

    notify("trophy_unlocker: V75 signatures PS4=%d", count);
    return count;
}

static int
scan_ps4_trophy1_context(int32_t handle,
                         int32_t *ctx_out,
                         SceNpTrophyGameDetails *details_out)
{
    SceNpTrophyGameDetails probe;
    int best_ctx = SCE_NP_TROPHY_INVALID_CONTEXT;
    int rc;

    if (ctx_out == NULL || details_out == NULL ||
        handle == SCE_NP_TROPHY_INVALID_HANDLE)
        return -1;

    notify("trophy_unlocker: V77 scan PS4 ctx 0x%08x..0x%08x",
           TROPHY1_CONTEXT_SCAN_BASE,
           TROPHY1_CONTEXT_SCAN_BASE + TROPHY1_CONTEXT_SCAN_LIMIT - 1);

    for (int ctx = TROPHY1_CONTEXT_SCAN_BASE;
         ctx < TROPHY1_CONTEXT_SCAN_BASE + TROPHY1_CONTEXT_SCAN_LIMIT;
         ctx++) {
        memset(&probe, 0, sizeof probe);
        probe.size = sizeof probe;

        rc = p_RegisterContext(ctx, handle, 0);
        if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_INVALID_CONTEXT) {
            if ((ctx & 0xff) == 0)
                logf("V79 PS4 scan ctx=0x%08x invalid... continuing",
                     ctx);
            continue;
        }
        logf("V79 PS4 scan RegisterContext ctx=0x%08x h=%d -> 0x%08x",
             ctx, handle, rc);
        if (rc != 0 &&
            (uint32_t)rc != SCE_NP_TROPHY_ERROR_ALREADY_REGISTERED)
            continue;

        rc = p_GetGameInfo(ctx, handle, &probe, NULL);
        logf("V79 PS4 scan GetGameInfo ctx=0x%08x -> 0x%08x num=%u title='%.*s'",
             ctx, rc, probe.numTrophies, 48, probe.title);
        if (rc == 0 && probe.numTrophies > 0 &&
            probe.numTrophies <= TROPHY_UNLOCKER_MAX_ALL) {
            best_ctx = ctx;
            memcpy(details_out, &probe, sizeof probe);
            break;
        }
    }

    if (best_ctx == SCE_NP_TROPHY_INVALID_CONTEXT) {
        notify("trophy_unlocker: V77 contexte PS4 existant introuvable");
        return -1;
    }

    *ctx_out = best_ctx;
    notify("trophy_unlocker: V77 contexte PS4=0x%08x trophies=%u",
           best_ctx, details_out->numTrophies);
    return 0;
}

static int
run_ps4_trophy1_unlock(int argc, char *argv[])
{
    int32_t ctx = SCE_NP_TROPHY_INVALID_CONTEXT;
    int32_t handle = SCE_NP_TROPHY_INVALID_HANDLE;
    SceUserServiceUserId user_id = SCE_USER_SERVICE_USER_ID_INVALID;
    SceNpCommunicationId comm_id;
    SceNpCommunicationSignature comm_sig;
    SceNpCommunicationSignature sig_candidates[TROPHY_UNLOCKER_MAX_SIG_CANDIDATES];
    SceNpTrophyGameDetails details;
    uint32_t num_trophies = 0;
    int lo = 0;
    int hi = 0;
    int unlocked = 0;
    int already = 0;
    int invalid = 0;
    int errors = 0;
    int created_context = 0;
    int have_details = 0;
    int rc;

    if (resolve_ps4_trophy1_symbols() != 0)
        return 1;

    if (get_initial_user_id(&user_id) != 0) {
        notify("trophy_unlocker: V76 initial user PS4 failed");
        return 1;
    }

    if (argc >= 2 && strncmp(argv[1], "NPWR", 4) == 0) {
        if (parse_npcommid(argv[1], &comm_id) != 0) {
            notify("trophy_unlocker: V73 NPWR invalide '%s'", argv[1]);
            return 1;
        }
    } else if (detect_ps4_npcomm(&comm_id) != 0) {
        logf("V76 PS4 NPWR unavailable; continuing with current title context");
    }

    memset(&comm_sig, 0, sizeof comm_sig);
    memset(sig_candidates, 0, sizeof sig_candidates);
    memset(&details, 0, sizeof details);
    details.size = sizeof details;

    (void)comm_sig;
    (void)read_ps4_signature_candidates(sig_candidates,
                                        TROPHY_UNLOCKER_MAX_SIG_CANDIDATES);

    rc = p_CreateContext(&ctx, user_id, 0, 0);
    logf("V76 CreateContext(user=%d label=0 npwr=%.9s_%02u) -> 0x%08x ctx=%d",
         user_id, comm_id.data, comm_id.num, rc, ctx);
    if (rc == 0) {
        created_context = 1;
        notify("trophy_unlocker: V76 CreateContext OK user=%d", user_id);
    } else if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_CONTEXT_ALREADY_EXISTS) {
        notify("trophy_unlocker: V77 contexte existe, scan...");
    } else {
        notify("trophy_unlocker: V76 CreateContext bloque 0x%08x", rc);
        return 2;
    }

    rc = p_CreateHandle(&handle);
    logf("V73 CreateHandle -> 0x%08x h=%d", rc, handle);
    if (rc != 0) {
        notify("trophy_unlocker: V73 CreateHandle bloque 0x%08x", rc);
        if (created_context)
            p_DestroyContext(ctx);
        return 3;
    }

    if (!created_context) {
        if (scan_ps4_trophy1_context(handle, &ctx, &details) != 0) {
            p_DestroyHandle(handle);
            return 4;
        }
        have_details = 1;
    } else {
        rc = p_RegisterContext(ctx, handle, 0);
        logf("V73 RegisterContext -> 0x%08x", rc);
        if (rc != 0) {
            notify("trophy_unlocker: V73 RegisterContext bloque 0x%08x", rc);
            p_DestroyHandle(handle);
            p_DestroyContext(ctx);
            return 4;
        }
    }

    if (!have_details) {
        rc = p_GetGameInfo(ctx, handle, &details, NULL);
        logf("V73 GetGameInfo -> 0x%08x num=%u title='%.*s'",
             rc, details.numTrophies, 64, details.title);
    } else {
        rc = 0;
        logf("V77 GetGameInfo reused ctx=0x%08x num=%u title='%.*s'",
             ctx, details.numTrophies, 64, details.title);
    }
    if (rc == 0 && details.numTrophies > 0 &&
        details.numTrophies <= TROPHY_UNLOCKER_MAX_ALL) {
        num_trophies = details.numTrophies;
        notify("trophy_unlocker: V73 PS4 trophies=%u", num_trophies);
    } else {
        num_trophies = ensure_trophy_count(0, "ps4-trophy1");
    }

    if (select_unlock_range(argc, argv, num_trophies, &lo, &hi) != 0) {
        p_DestroyHandle(handle);
        p_DestroyContext(ctx);
        return 5;
    }

    notify("trophy_unlocker: V73 PS4 unlock %d..%d", lo, hi);
    for (int id = lo; id <= hi && id < TROPHY_UNLOCKER_MAX_ALL; id++) {
        int32_t platinum_id = SCE_NP_TROPHY_INVALID_TROPHY_ID;

        rc = p_UnlockTrophy(ctx, handle, id, &platinum_id);
        logf("V73 UnlockTrophy(%d) -> 0x%08x platinum=%d",
             id, rc, platinum_id);
        if (rc == 0) {
            unlocked++;
        } else if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_TROPHY_ALREADY_UNLOCKED) {
            already++;
        } else if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_INVALID_TROPHY_ID) {
            invalid++;
        } else {
            errors++;
        }
        if (PS4_UNLOCK_EVENT_DELAY_USEC > 0)
            sceKernelUsleep(PS4_UNLOCK_EVENT_DELAY_USEC);
    }

    p_DestroyHandle(handle);
    if (created_context)
        p_DestroyContext(ctx);

    notify("trophy_unlocker: V73 PS4 done new=%d deja=%d invalid=%d err=%d",
           unlocked, already, invalid, errors);
    return errors ? 6 : 0;
}

static int __attribute__((unused))
file_exists_ro(const char *path)
{
    int fd = open(path, O_RDONLY, 0);

    if (fd < 0)
        return 0;
    close(fd);
    return 1;
}

static int __attribute__((unused))
read_platform_override(char *out, size_t out_sz)
{
    int fd;
    int n;
    size_t j = 0;

    if (out == NULL || out_sz == 0)
        return -1;
    out[0] = '\0';

    fd = open(TROPHY_UNLOCKER_PLATFORM_FILE, O_RDONLY, 0);
    if (fd < 0) {
        logf("V78 platform override open(%s) -> %d",
             TROPHY_UNLOCKER_PLATFORM_FILE, fd);
        return -1;
    }

    n = read(fd, g_ucp_scan_buf, 31);
    close(fd);
    if (n <= 0)
        return -1;

    for (int i = 0; i < n && j + 1 < out_sz; i++) {
        char c = (char)g_ucp_scan_buf[i];

        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
            break;
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + ('a' - 'A'));
        out[j++] = c;
    }
    out[j] = '\0';

    logf("V78 platform override='%s'", out);
    return j > 0 ? 0 : -1;
}

static int __attribute__((unused))
should_use_ps4_trophy1_mode(void)
{
    char platform[16];
    uint32_t trophy1_h = 0;
    uint32_t trophy2_h = 0;
    uint32_t uds_h = 0;
    int has_trophy2_pkg;
    int has_trophy1_pkg;
    int rc1;
    int rc2;
    int rcu;

    if (read_platform_override(platform, sizeof platform) == 0) {
        if (strncmp(platform, "ps4", 3) == 0 ||
            strncmp(platform, "cusa", 4) == 0) {
            notify("trophy_unlocker: V78 route forcee PS4");
            return 1;
        }
        if (strncmp(platform, "ps5", 3) == 0 ||
            strncmp(platform, "ppsa", 4) == 0) {
            notify("trophy_unlocker: V78 route forcee PS5");
            return 0;
        }
    }

    rc1 = kernel_dynlib_handle(getpid(), "libSceNpTrophy.sprx", &trophy1_h);
    rc2 = kernel_dynlib_handle(getpid(), "libSceNpTrophy2.sprx", &trophy2_h);
    rcu = kernel_dynlib_handle(getpid(), "libSceNpUniversalDataSystem.sprx",
                               &uds_h);
    has_trophy2_pkg = file_exists_ro("/app0/sce_sys/trophy2/trophy00.ucp");
    has_trophy1_pkg =
        file_exists_ro("/app0/sce_sys/trophy/trophy00.trp") ||
        file_exists_ro("/app0/sce_sys/trophy/trophy00.ucp");

    logf("V78 auto route rc1=0x%08x h1=0x%08x rc2=0x%08x h2=0x%08x rcu=0x%08x uds=0x%08x pkg2=%d pkg1=%d",
         rc1, trophy1_h, rc2, trophy2_h, rcu, uds_h,
         has_trophy2_pkg, has_trophy1_pkg);

    if (trophy2_h != 0 || uds_h != 0 || has_trophy2_pkg) {
        notify("trophy_unlocker: V78 auto route PS5/Trophy2");
        return 0;
    }

    if (trophy1_h != 0 || has_trophy1_pkg) {
        notify("trophy_unlocker: V78 auto route PS4/Trophy1");
        return 1;
    }

    notify("trophy_unlocker: V78 route inconnue, essai PS5");
    return 0;
}

/* ---------------------------------------------------------------- main */

int
main(int argc, char *argv[])
{
    SceUserServiceUserId user_id = SCE_USER_SERVICE_USER_ID_INVALID;
    SceNpTrophy2Context trophy_ctx = SCE_NP_TROPHY2_INVALID_CONTEXT;
    SceNpTrophy2Handle trophy_handle = SCE_NP_TROPHY2_INVALID_HANDLE;
    SceNpUniversalDataSystemContext uds_ctx =
        SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
    SceNpUniversalDataSystemHandle uds_reg_handle =
        SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE;
    SceNpTrophy2GameDetails game_details;
    SceNpTrophy2GameData game_data;
    int lo = DEFAULT_TROPHY_ID;
    int hi = DEFAULT_TROPHY_ID;
    int posted = 0;
    int errors = 0;
    int uds_register_ok = 0;
    uint32_t uds_register_rc = 0;
    int uds_init_done = 0;
    SceNpServiceLabel uds_service_label = 0;
    int trophy_callback_registered = 0;
    int rc;

    log_init();
    uint32_t num_trophies = 0;

    logf("BUILD %s pid=%d", BUILD_TAG, getpid());
    notify("trophy_unlocker: %s pid=%d", BUILD_TAG, getpid());
    probe_app0_trophy_package_files();

    logf("DEBUG V26: main entered argc=%d arg1=%s",
         argc, argc >= 2 ? argv[1] : "<none>");
    notify("DEBUG V26: START argc=%d arg1=%s",
           argc, argc >= 2 ? argv[1] : "<none>");

    if (getpid() == 56 || getpid() == 57) {
        run_shellcore_trophy_service_diag();
        log_drain();
        return 0;
    }

    if (ENABLE_PS4_TROPHY1_MODE &&
        (!ENABLE_AUTO_PS4_PS5_MODE || should_use_ps4_trophy1_mode())) {
        rc = run_ps4_trophy1_unlock(argc, argv);
        log_drain();
        return rc;
    }

    if (ENABLE_PS4_TROPHY1_MODE && ENABLE_AUTO_PS4_PS5_MODE)
        notify("trophy_unlocker: V78 continue branche PS5");

    if (dl_resolve_all() != 0) {
        log_drain();
        return 1;
    }

    if (get_initial_user_id(&user_id) != 0) {
        notify("trophy_unlocker: V22 initial user failed");
        log_drain();
        return 2;
    }

    if (ENABLE_UDS_LIVE_CONTEXT_FILE) {
        rc = run_live_context_unlock_from_file(argc, argv);
        log_drain();
        return rc == 0 ? 0 : 7;
    }

    if (ENABLE_UDS_POSTEVENT_HOOK) {
        rc = run_uds_postevent_hook_monitor(UDS_HOOK_MONITOR_SECONDS,
                                            argc, argv);
        log_drain();
        return rc == 0 ? 0 : 6;
    }

    SceNpUniversalDataSystemInitParam init_param;
    memset(&init_param, 0, sizeof init_param);
    init_param.size = sizeof init_param;
    init_param.poolSize = UDS_POOL_SIZE;
    rc = p_UdsInitialize(&init_param);
    logf("V37 UDS Initialize before Trophy2(pool=%zu) -> 0x%08x",
         init_param.poolSize, rc);
    if (rc >= 0 || (uint32_t)rc == UDS_ERROR_ALREADY_INITIALIZED_RC) {
        uds_init_done = 1;
        notify("trophy_unlocker: V37 UDS init OK rc=0x%08x", rc);
    } else {
        notify("trophy_unlocker: V37 UDS init bloque 0x%08x", rc);
    }

    notify("DEBUG V26: optional Trophy2 probe user=%d ok=%d uds_only=%d",
           user_id, g_trophy2_symbols_ok, g_uds_only_mode);
    if (g_trophy2_symbols_ok && p_Trophy2RegisterUnlockCallback != NULL) {
        rc = p_Trophy2RegisterUnlockCallback(trophy2_unlock_callback, NULL);
        logf("V26 Trophy2 RegisterUnlockCallback -> 0x%08x", rc);
        notify("trophy_unlocker: V26 UnlockCallback rc=0x%08x", rc);
        if (rc >= 0)
            trophy_callback_registered = 1;
    } else {
        logf("V26 Trophy2 RegisterUnlockCallback unavailable");
        notify("trophy_unlocker: V26 UnlockCallback absent");
    }

    if (ENABLE_CALLBACK_MONITOR) {
        int cb_total = monitor_trophy2_unlock_callbacks(CALLBACK_MONITOR_SECONDS);

        if (trophy_callback_registered &&
            p_Trophy2UnregisterUnlockCallback != NULL) {
            rc = p_Trophy2UnregisterUnlockCallback();
            logf("V49 Trophy2 UnregisterUnlockCallback -> 0x%08x", rc);
        }

        logf("V49 monitor exit cb_total=%d", cb_total);
        log_drain();
        return 0;
    }

    pump_np_callbacks("before-trophy-create", 2);

    if (ENABLE_HEAP_CONTEXT_SCAN)
        scan_known_np_heaps_for_candidates();

    if (g_trophy2_symbols_ok && ENABLE_TROPHY2_CANDIDATE_INFO_TEST)
        test_trophy2_candidate_get_info(&num_trophies);

    if (g_trophy2_symbols_ok && ENABLE_THREADED_REGISTER_PROBE)
        (void)run_threaded_trophy2_register_probe(user_id, &num_trophies);

    if (g_trophy2_symbols_ok && ENABLE_TROPHY2_CONTEXT_SCAN)
        (void)scan_existing_trophy2_contexts(&num_trophies);

    if (!g_trophy2_symbols_ok) {
        logf("V67 UDS-only mode: skip Trophy2 Create/Register; default num_trophies=%u",
             num_trophies);
        notify("trophy_unlocker: V67 mode UDS-only");
        goto skip_trophy_register_probe;
    }

    if (!ENABLE_REGISTER_PROBES) {
        logf("V32 skip legacy inline RegisterContext probes; diagnostic mode");
        notify("trophy_unlocker: V32 skip inline probes");
        goto skip_trophy_register_probe;
    }

    rc = p_Trophy2CreateContext(&trophy_ctx, user_id, 0, 0);
    logf("V23 Trophy2 CreateContext -> 0x%08x ctx=%d", rc, trophy_ctx);
    if (rc < 0) {
        notify("trophy_unlocker: Trophy2 probe refused 0x%08x, trying UDS", rc);
        logf("V69 Trophy2 CreateContext label0 failed; probing service labels then rescanning contexts");
        (void)scan_trophy2_service_labels(user_id, &trophy_ctx,
                                          &trophy_handle, &num_trophies);
        (void)scan_existing_trophy2_contexts(&num_trophies);
    } else {
        pump_np_callbacks("after-trophy-create", 2);
        rc = p_Trophy2CreateHandle(&trophy_handle);
        logf("V23 Trophy2 CreateHandle -> 0x%08x h=%d", rc, trophy_handle);
        if (rc < 0) {
            notify("trophy_unlocker: Trophy2 handle refused 0x%08x, trying UDS", rc);
        } else {
            pump_np_callbacks("before-trophy-register", 2);
            rc = p_Trophy2RegisterContext(trophy_ctx, trophy_handle, 0);
            logf("V23 Trophy2 RegisterContext -> 0x%08x", rc);
            notify("trophy_unlocker: Trophy2 Register rc=0x%08x", rc);
            pump_np_callbacks("after-trophy-register", 6);
            if (rc < 0) {
                logf("V23 Trophy2 RegisterContext failed; continuing with UDS-only unlock path");
                notify("trophy_unlocker: Trophy2 bloque 0x%08x, test UDS", rc);
                destroy_trophy2_pair(&trophy_ctx, &trophy_handle,
                                     "label0-register-failed");
                (void)scan_trophy2_service_labels(user_id, &trophy_ctx,
                                                  &trophy_handle,
                                                  &num_trophies);
            } else {
                memset(&game_details, 0, sizeof game_details);
                memset(&game_data, 0, sizeof game_data);
                rc = p_Trophy2GetGameInfo(trophy_ctx, trophy_handle,
                                          &game_details, &game_data);
                logf("V23 Trophy2 GetGameInfo -> 0x%08x num=%u unlocked=%u title='%.*s'",
                     rc, game_details.numTrophies, game_data.unlockedTrophies,
                     64, game_details.title);
                notify("trophy_unlocker: Trophy2 info rc=0x%08x trophies=%u unlocked=%u",
                       rc, game_details.numTrophies, game_data.unlockedTrophies);
                if (rc < 0) {
                    logf("V23 Trophy2 GetGameInfo failed; continuing with default UDS selection");
                    notify("trophy_unlocker: Trophy2 info refused 0x%08x, trying UDS", rc);
                } else {
                    num_trophies = game_details.numTrophies;
                }
            }
        }
    }

skip_trophy_register_probe:
    num_trophies = ensure_trophy_count(num_trophies, "main-unlock");
    if (select_unlock_range(argc, argv, num_trophies, &lo, &hi) != 0) {
        errors++;
        goto cleanup;
    }

    if (!ENABLE_UDS_CONTEXT_SCAN && !ENABLE_REGISTER_PROBES) {
        logf("V32 diagnostic done: no UDS post/register attempted");
        notify("trophy_unlocker: V32 diagnostic seul, pas d'UDS");
        goto cleanup;
    }

    if (!uds_init_done)
        logf("V37 continuing UDS path even though init did not report OK");
    pump_np_callbacks("after-uds-initialize", 2);

    if (ENABLE_EXISTING_UDS_CONTEXT_FULL_POST && ENABLE_UDS_CONTEXT_SCAN) {
        SceNpUniversalDataSystemContext found_uds_ctx =
            SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT;
        int probe_id = select_uds_probe_trophy_id(lo, hi);

        logf("V60 existing ctx full post enabled range=%d..%d probe_id=%d",
             lo, hi, probe_id);
        if (find_existing_uds_context_with_probe(probe_id,
                SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT,
                &found_uds_ctx) == 0) {
            rc = post_trophy_range_on_existing_uds_context(found_uds_ctx,
                                                           lo, hi);
            if (rc >= 0)
                posted += rc;
            else
                errors++;
            if (g_trophy2_symbols_ok)
                run_trophy2_post_info_diag(trophy_ctx, trophy_handle, lo, hi,
                                           "after-v60-existing-all");
            goto cleanup;
        }

        logf("V60 no existing UDS ctx accepted; fallback to normal path");
    }

    if (ENABLE_UDS_CONTEXT_SCAN && (hi - lo) <= 4) {
        notify("trophy_unlocker: V28 test contexte UDS deja existant");
        try_existing_uds_contexts(lo, hi,
                                  SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT,
                                  &posted);
        if (posted > 0) {
            logf("V40 settle after existing UDS post usec=%d",
                 POST_UNLOCK_SETTLE_USEC);
            sceKernelUsleep(POST_UNLOCK_SETTLE_USEC);
            pump_np_callbacks("after-existing-uds-posts",
                              POST_UNLOCK_FINAL_PUMP_COUNT);
            if (g_trophy2_symbols_ok)
                run_trophy2_post_info_diag(trophy_ctx, trophy_handle, lo, hi,
                                           "after-existing-uds");
            goto cleanup;
        }
    } else {
        logf("V28 skip existing UDS context scan for large id range %d..%d",
             lo, hi);
    }

    if (!ENABLE_REGISTER_PROBES) {
        logf("V34 existing UDS scan only: skip Create/RegisterContext posted=%d",
             posted);
        notify("trophy_unlocker: V34 scan UDS fini posted=%d", posted);
        goto cleanup;
    }

    rc = p_UdsCreateContext(&uds_ctx, user_id, 0, 0);
    logf("V23 UDS CreateContext -> 0x%08x ctx=%d", rc, uds_ctx);
    if (rc < 0) {
        notify("trophy_unlocker: UDS CreateContext FAILED 0x%08x", rc);
        goto cleanup;
    }

    rc = p_UdsCreateHandle(&uds_reg_handle);
    logf("V23 UDS CreateHandle(register) -> 0x%08x h=%d", rc, uds_reg_handle);
    if (rc < 0)
        goto cleanup;

    pump_np_callbacks("before-uds-register", 2);
    rc = p_UdsRegisterContext(uds_ctx, uds_reg_handle, 0);
    uds_register_rc = (uint32_t)rc;
    logf("V24 UDS RegisterContext -> 0x%08x", rc);
    notify("trophy_unlocker: UDS Register rc=0x%08x", rc);
    pump_np_callbacks("after-uds-register", 6);
    if (rc < 0) {
        logf("V24 UDS RegisterContext failed; testing PostEvent anyway");
        notify("trophy_unlocker: UDS label 0 bloque 0x%08x", rc);
        destroy_uds_pair(&uds_ctx, &uds_reg_handle, "label0-register-failed");
        if (scan_uds_service_labels(user_id, &uds_ctx, &uds_reg_handle,
                                    &uds_service_label) == 0) {
            uds_register_ok = 1;
            uds_register_rc = 0;
        } else {
            if (ENABLE_UDS_CONTEXT_SCAN && (hi - lo) <= 4) {
                notify("trophy_unlocker: V28 re-scan apres labels refuses");
                try_existing_uds_contexts(lo, hi,
                                          SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT,
                                          &posted);
                if (posted > 0)
                    goto cleanup;
            }
            notify("trophy_unlocker: V27 pas de contexte UDS enregistre");
            errors++;
            goto cleanup;
        }
    } else {
        uds_register_ok = 1;
    }

    notify("trophy_unlocker: V27 posting _UnlockTrophy %d..%d label=%u",
           lo, hi, uds_service_label);
    for (int id = lo; id <= hi; id++) {
        rc = post_unlock_trophy_event(uds_ctx, id);
        if (rc < 0) {
            errors++;
            notify("trophy_unlocker: _UnlockTrophy(%d) rc=0x%08x", id, rc);
        } else {
            posted++;
            notify("trophy_unlocker: _UnlockTrophy(%d) posted", id);
            pump_np_callbacks("after-unlock-post", POST_UNLOCK_CALLBACK_PUMP_COUNT);
        }
        sceKernelUsleep(POST_UNLOCK_EVENT_DELAY_USEC);
    }

    if (posted > 0) {
        logf("V40 settle after posts usec=%d", POST_UNLOCK_SETTLE_USEC);
        sceKernelUsleep(POST_UNLOCK_SETTLE_USEC);
    }
    pump_np_callbacks("after-all-unlock-posts", POST_UNLOCK_FINAL_PUMP_COUNT);

    if (posted > 0 && g_trophy2_symbols_ok)
        run_trophy2_post_info_diag(trophy_ctx, trophy_handle, lo, hi,
                                   "after-posts");

    if (posted == 0 && !uds_register_ok &&
        uds_register_rc == REGISTER_CONTEXT_REFUSED_RC &&
        ENABLE_UDS_CONTEXT_SCAN && (hi - lo) <= 4) {
        try_existing_uds_contexts(lo, hi, uds_ctx, &posted);
    }

cleanup:
    if (uds_reg_handle != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_HANDLE) {
        rc = p_UdsDestroyHandle(uds_reg_handle);
        logf("V22 UDS DestroyHandle(register) -> 0x%08x", rc);
    }
    if (uds_ctx != SCE_NP_UNIVERSAL_DATA_SYSTEM_INVALID_CONTEXT) {
        rc = p_UdsDestroyContext(uds_ctx);
        logf("V22 UDS DestroyContext -> 0x%08x", rc);
    }
    if (g_trophy2_symbols_ok &&
        trophy_handle != SCE_NP_TROPHY2_INVALID_HANDLE) {
        rc = p_Trophy2DestroyHandle(trophy_handle);
        logf("V22 Trophy2 DestroyHandle -> 0x%08x", rc);
    }
    if (g_trophy2_symbols_ok &&
        trophy_ctx != SCE_NP_TROPHY2_INVALID_CONTEXT) {
        rc = p_Trophy2DestroyContext(trophy_ctx);
        logf("V22 Trophy2 DestroyContext -> 0x%08x", rc);
    }
    if (trophy_callback_registered &&
        p_Trophy2UnregisterUnlockCallback != NULL) {
        rc = p_Trophy2UnregisterUnlockCallback();
        logf("V26 Trophy2 UnregisterUnlockCallback -> 0x%08x", rc);
    }

    notify("trophy_unlocker: V32 done posted=%d errors=%d", posted, errors);
    log_drain();
    return errors ? 5 : 0;
}
