/* PS5 trophy unlocker — homebrew payload for jailbroken consoles.
 *
 * Designed for John Törnblom's ps5-payload-elfldr (TCP 9021).
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
int sceSysmoduleLoadModuleInternal(uint32_t id);

/* sockets (FreeBSD-style; we link libkernel_web which re-exports them) */
int  socket(int, int, int);
int  bind(int, const void *, int);
int  listen(int, int);
int  accept(int, void *, int *);
int  setsockopt(int, int, int, const void *, int);
int  send(int, const void *, size_t, int);
int  close(int);

#define AF_INET            2
#define SOCK_STREAM        1
#define SOL_SOCKET     0xFFFF
#define SO_REUSEADDR    0x0004
#define INADDR_ANY     0x00000000

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

#define LOG_PORT       9022
#define LOG_BUFSZ      (64 * 1024)   /* 64 KiB ring */
#define LOG_HOLD_MS    (15 * 1000)   /* keep listener alive 15s post-main */

static char     log_buf[LOG_BUFSZ];
static size_t   log_head;    /* next write offset (linear; not wrapped) */
static int      log_clients[8];
static int      log_n_clients;
static int      log_listener_running;

static void
log_append_raw(const char *s, size_t n)
{
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
notify(const char *fmt, ...)
{
    char  line[1024];
    int   n;

    va_list ap;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof line) n = sizeof line - 1;

    /* 1. Toast on the PS5 (one-line summary). */
    notify_request_t req;
    memset(&req, 0, sizeof req);
    memcpy(req.message, line, (size_t)n);
    sceKernelSendNotificationRequest(0, &req, sizeof req, 0);

    /* 2. Append to log buffer + push to TCP clients. */
    log_append_raw(line, (size_t)n);
    log_append_raw("\n", 1);

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
    if (s < 0) return NULL;

    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_len    = sizeof sa;
    sa.sin_family = AF_INET;
    sa.sin_port   = htons16(LOG_PORT);
    sa.sin_addr   = INADDR_ANY;

    if (bind(s, &sa, sizeof sa) < 0) {
        close(s);
        return NULL;
    }
    if (listen(s, 4) < 0) {
        close(s);
        return NULL;
    }
    log_listener_running = 1;

    for (;;) {
        struct sockaddr_in ca;
        int calen = sizeof ca;
        int c = accept(s, &ca, &calen);
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
    for (int i = 0; i < (int)(sizeof log_clients / sizeof log_clients[0]); i++)
        log_clients[i] = -1;

    ScePthread th;
    int rc = scePthreadCreate(&th, NULL, log_listener_thread, NULL,
                              "trophy_log");
    if (rc == 0) {
        scePthreadDetach(th);
        /* Give the listener a moment to bind before main starts pushing
         * messages — clients connecting right away won't miss the early
         * lines because log_append_raw also appends to the in-memory
         * buffer, which is replayed on accept(). */
        sceKernelUsleep(50000);
    }
}

static void
log_drain(void)
{
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

#define SCE_NP_TROPHY_INVALID_TROPHY_ID             (-1)
#define SCE_NP_TROPHY_INVALID_HANDLE                (-1)
#define SCE_NP_TROPHY_INVALID_CONTEXT               (-1)
#define SCE_NP_TROPHY_ERROR_TROPHY_ALREADY_UNLOCKED 0x80551611
#define SCE_NP_TROPHY_ERROR_INVALID_TROPHY_ID       0x80551606

static int (*p_CreateContext) (int32_t *, const SceNpCommunicationId *,
                               const SceNpCommunicationSignature *, uint64_t);
static int (*p_DestroyContext)(int32_t);
static int (*p_CreateHandle)  (int32_t *);
static int (*p_DestroyHandle) (int32_t);
static int (*p_RegisterContext)(int32_t, int32_t, uint64_t);
static int (*p_GetGameInfo)   (int32_t, int32_t, SceNpTrophyGameDetails *, void *);
static int (*p_UnlockTrophy)  (int32_t, int32_t, int32_t, int32_t *);
static int (*p_GetRunning)    (int32_t, SceNpCommunicationId *);

static int trophy_h = -1;

static int
dl_resolve_all(void)
{
    int rc;
    static const struct { const char *path; const char *tag; } paths[] = {
        { "libSceNpTrophy.sprx",                       "bare"    },
        { "/system/common/lib/libSceNpTrophy.sprx",    "common"  },
        { "/system_ex/priv_ex/lib/libSceNpTrophy.sprx","priv_ex" },
        { "/system/priv/lib/libSceNpTrophy.sprx",      "priv"    },
        { "/app0/sce_module/libSceNpTrophy.sprx",      "app0"    },
        { NULL, NULL }
    };

    for (int i = 0; paths[i].path; i++) {
        logf("LoadStartModule(%s) ...", paths[i].path);
        rc = sceKernelLoadStartModule(paths[i].path, 0, NULL, 0, NULL, NULL);
        logf("LoadStartModule(%s) -> 0x%08x", paths[i].tag, rc);
        if (rc >= 0) { trophy_h = rc; break; }
    }

    if (trophy_h < 0) {
        logf("trying sceSysmoduleLoadModuleInternal(0x80000022) ...");
        rc = sceSysmoduleLoadModuleInternal(0x80000022);
        logf("sysmodInt(0x80000022) -> 0x%08x", rc);
        if (rc != 0) {
            logf("trying sceSysmoduleLoadModuleInternal(0x80000020) ...");
            rc = sceSysmoduleLoadModuleInternal(0x80000020);
            logf("sysmodInt(0x80000020) -> 0x%08x", rc);
        }
        if (rc == 0) {
            rc = sceKernelLoadStartModule(
                "/system/common/lib/libSceNpTrophy.sprx",
                0, NULL, 0, NULL, NULL);
            logf("post-sysmod LoadStart -> 0x%08x", rc);
            if (rc >= 0) trophy_h = rc;
        }
    }

    if (trophy_h < 0) {
        notify("trophy_unlocker: module load FAILED (see log on :9022)");
        return -1;
    }
    notify("trophy_unlocker: libSceNpTrophy loaded (h=%d)", trophy_h);

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
        int r = sceKernelDlsym(trophy_h, syms[i].name, syms[i].slot);
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

static int
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

/* ---------------------------------------------------------------- main */

int
main(int argc, char *argv[])
{
    log_init();
    notify("trophy_unlocker: started (argc=%d, arg1=%s) — log on tcp/%d",
           argc, argc >= 2 ? argv[1] : "<none>", LOG_PORT);

    if (dl_resolve_all() != 0) {
        log_drain();
        return 1;
    }

    int32_t ctx = SCE_NP_TROPHY_INVALID_CONTEXT;
    int32_t h   = SCE_NP_TROPHY_INVALID_HANDLE;
    SceNpCommunicationId         commId;
    SceNpCommunicationSignature  commSig;
    int rc;
    int unlocked = 0, already = 0, errors = 0;
    int32_t one_only = -1;

    memset(&commSig, 0, sizeof commSig);

    if (argc < 2) {
        memset(&commId, 0, sizeof commId);
        if (p_GetRunning == NULL) {
            notify("trophy_unlocker: no arg and GetRunningTitle missing");
            log_drain();
            return 1;
        }
        rc = p_GetRunning(0, &commId);
        logf("IntGetRunningTitle -> 0x%08x  data=%.9s num=%u",
             rc, commId.data, commId.num);
        if (rc != 0 || commId.data[0] == 0) {
            notify("trophy_unlocker: auto-detect failed 0x%08x", rc);
            log_drain();
            return 1;
        }
        notify("trophy_unlocker: detected %.9s_%02u", commId.data, commId.num);
    } else {
        if (parse_npcommid(argv[1], &commId) != 0) {
            notify("trophy_unlocker: bad NpCommId '%s'", argv[1]);
            log_drain();
            return 1;
        }
        if (argc >= 3) {
            int id = (int)strtol(argv[2], NULL, 10);
            if (id < 0 || id > 127) {
                notify("trophy_unlocker: id %d out of range", id);
                log_drain();
                return 1;
            }
            one_only = id;
        }
    }

    logf("CreateContext(%.9s_%02u)", commId.data, commId.num);
    rc = p_CreateContext(&ctx, &commId, &commSig, 0);
    logf("CreateContext -> 0x%08x  ctx=%d", rc, ctx);
    if (rc != 0) {
        notify("trophy_unlocker: CreateContext FAILED 0x%08x", rc);
        log_drain();
        return 2;
    }

    rc = p_CreateHandle(&h);
    logf("CreateHandle -> 0x%08x  h=%d", rc, h);
    if (rc != 0) {
        notify("trophy_unlocker: CreateHandle FAILED 0x%08x", rc);
        p_DestroyContext(ctx);
        log_drain();
        return 3;
    }

    rc = p_RegisterContext(ctx, h, 0);
    logf("RegisterContext -> 0x%08x", rc);
    if (rc != 0) {
        notify("trophy_unlocker: RegisterContext FAILED 0x%08x", rc);
        p_DestroyHandle(h);
        p_DestroyContext(ctx);
        log_drain();
        return 4;
    }

    SceNpTrophyGameDetails det;
    memset(&det, 0, sizeof det);
    det.size = sizeof det;
    rc = p_GetGameInfo(ctx, h, &det, NULL);
    logf("GetGameInfo -> 0x%08x  numTrophies=%u title='%.*s'",
         rc, det.numTrophies, 64, det.title);

    int lo = 0, hi;
    if (one_only >= 0) {
        lo = hi = one_only;
    } else if (rc == 0 && det.numTrophies > 0 && det.numTrophies <= 128) {
        hi = (int)det.numTrophies - 1;
        notify("trophy_unlocker: '%.*s' has %u trophies — unlocking",
               48, det.title, det.numTrophies);
    } else {
        hi = 127;
        notify("trophy_unlocker: GameInfo 0x%08x — scanning 0..127", rc);
    }

    for (int id = lo; id <= hi; id++) {
        int32_t plat = SCE_NP_TROPHY_INVALID_TROPHY_ID;
        rc = p_UnlockTrophy(ctx, h, id, &plat);
        logf("UnlockTrophy(%d) -> 0x%08x  plat=%d", id, rc, plat);
        if (rc == 0)
            unlocked++;
        else if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_TROPHY_ALREADY_UNLOCKED)
            already++;
        else if ((uint32_t)rc == SCE_NP_TROPHY_ERROR_INVALID_TROPHY_ID)
            ;
        else
            errors++;
    }

    p_DestroyHandle(h);
    p_DestroyContext(ctx);

    notify("trophy_unlocker: done — %d unlocked, %d already, %d errors",
           unlocked, already, errors);
    log_drain();
    return errors ? 5 : 0;
}
