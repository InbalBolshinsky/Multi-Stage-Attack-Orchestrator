/*
 * Device simulator.
 *
 * Speaks a small length-prefixed text-payload protocol over TCP (see
 * PROTOCOL.md) and stands in for a real mobile device: it exposes device
 * info, "runs" attack stages with configurable success/failure, and once
 * "unlocked" serves reads from a tiny in-memory filesystem. It can also
 * simulate a connection that drops mid-chain, which is the main failure
 * mode the orchestrator has to handle gracefully.
 *
 * Every message (either direction) is [4-byte big-endian length][payload].
 * The length prefix means framing never depends on scanning for a
 * delimiter byte, so payload content -- including READ's file bytes -- can
 * safely contain '\n' or anything else.
 *
 * One client is served at a time (accept -> handle to completion -> accept
 * next). That's enough for an orchestrator that runs one attack at a time,
 * and it keeps the state machine trivial to reason about.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_LINE 4096
#define MAX_FAIL_STAGES 64
#define MAX_FILES 32
/* Sanity bound on an incoming frame's declared length -- this is a wire
 * boundary (untrusted input), so we bound it rather than trusting a
 * 4-byte length prefix to malloc() whatever it claims. */
#define MAX_FRAME (1 << 20)

typedef struct {
    const char *path;
    const char *content;
} FakeFile;

/* Default fake filesystem. Kept intentionally small and readable. */
static FakeFile g_files[MAX_FILES] = {
    {"/var/mobile/Library/db/contacts.db", "CONTACTS_DB_BINARY_BLOB_PLACEHOLDER"},
    {"/var/mobile/Library/db/messages.db", "MESSAGES_DB_BINARY_BLOB_PLACEHOLDER"},
    {"/var/mobile/Media/DCIM/100APPLE/IMG_0001.JPG", "JPEG_BYTES_PLACEHOLDER_1"},
    {"/var/mobile/Media/DCIM/100APPLE/IMG_0002.JPG", "JPEG_BYTES_PLACEHOLDER_2"},
    {"/var/mobile/Library/Notes/notes.sqlite", "NOTES_DB_BINARY_BLOB_PLACEHOLDER"},
};
static int g_file_count = 5;

typedef struct {
    char model[64];
    char ios_version[16];
    int battery;      /* 0-100 */
    int locked;       /* 1 = locked, 0 = unlocked */
    int fail_stages[MAX_FAIL_STAGES];
    int fail_stage_count;
    int drop_at_stage; /* stage id at which to silently close the connection; -1 = never */
    unsigned int seed;
} DeviceConfig;

static DeviceConfig g_cfg;

static int should_fail_stage(int stage_id) {
    for (int i = 0; i < g_cfg.fail_stage_count; i++) {
        if (g_cfg.fail_stages[i] == stage_id) return 1;
    }
    return 0;
}

static const char *find_file(const char *path) {
    for (int i = 0; i < g_file_count; i++) {
        if (strcmp(g_files[i].path, path) == 0) return g_files[i].content;
    }
    return NULL;
}

/* Reads exactly n bytes into buf, looping over short reads (a single
 * recv() is never guaranteed to fill the buffer). Returns n on success, 0
 * on clean EOF before any byte of this call was read (a clean close
 * between frames), -1 on error or an EOF mid-read (a partial frame --
 * treated the same as a dropped connection either way). */
static ssize_t read_exact(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char *)buf + got, n - got);
        if (r == 0) return (got == 0) ? 0 : -1;
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)r;
    }
    return (ssize_t)got;
}

/* Writes exactly n bytes, looping over short writes. Best-effort: a
 * broken pipe here just means the client dropped. */
static int write_exact(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char *)buf + sent, n - sent);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)w;
    }
    return 0;
}

/* Sends one length-prefixed frame: 4-byte big-endian length, then payload. */
static int send_frame(int fd, const void *payload, size_t len) {
    uint32_t len_be = htonl((uint32_t)len);
    if (write_exact(fd, &len_be, sizeof(len_be)) < 0) return -1;
    if (len > 0 && write_exact(fd, payload, len) < 0) return -1;
    return 0;
}

/* Formats a text payload and sends it as one frame. No trailing '\n' --
 * that was only needed for the old line-delimited framing. */
static void send_textf(int fd, const char *fmt, ...) {
    char buf[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1; /* truncate defensively */
    send_frame(fd, buf, (size_t)n);
}

/* Reads one length-prefixed frame into a heap buffer the caller must
 * free(). *out_payload is NUL-terminated for convenience parsing text
 * commands, in addition to the returned exact length. Returns positive
 * payload length on success, 0 for a clean close at a frame boundary
 * (equivalent to the old EOF-with-nothing-read case), -1 on error, an
 * oversized declared length, a partial frame, or a zero-length frame (no
 * real command is ever empty, so treat it the same as a malformed one --
 * this also means *out_payload is only ever set on the >0 return path,
 * so the caller always has exactly one buffer to free). */
static ssize_t read_frame(int fd, char **out_payload) {
    uint32_t len_be;
    ssize_t r = read_exact(fd, &len_be, sizeof(len_be));
    if (r <= 0) return r;
    uint32_t len = ntohl(len_be);
    if (len == 0 || len > MAX_FRAME) return -1;
    char *buf = malloc((size_t)len + 1);
    if (!buf) return -1;
    r = read_exact(fd, buf, len);
    if (r <= 0) { free(buf); return -1; } /* any EOF here is mid-frame */
    buf[len] = '\0';
    *out_payload = buf;
    return (ssize_t)len;
}

static void handle_hello(int fd) {
    send_textf(fd, "OK HELLO model=%s ios=%s battery=%d locked=%d",
               g_cfg.model, g_cfg.ios_version, g_cfg.battery, g_cfg.locked);
}

static void handle_stage(int fd, int stage_id) {
    /* NOTE: connection-drop for this stage is handled by the caller
     * (handle_connection) before we get here, since dropping means we must
     * not send any response at all. */
    if (should_fail_stage(stage_id)) {
        send_textf(fd, "OK STAGE %d FAIL", stage_id);
        return;
    }
    send_textf(fd, "OK STAGE %d SUCCESS", stage_id);
}

static void handle_unlock(int fd) {
    g_cfg.locked = 0;
    send_textf(fd, "OK UNLOCK locked=%d", g_cfg.locked);
}

static void handle_read(int fd, const char *path) {
    if (g_cfg.locked) {
        send_textf(fd, "ERR LOCKED");
        return;
    }
    const char *content = find_file(path);
    if (!content) {
        send_textf(fd, "ERR NOTFOUND %s", path);
        return;
    }
    /* Single frame: a text header, one embedded '\n', then the raw file
     * bytes. The receiver splits on the FIRST '\n' only and takes
     * everything else in the frame as content by length -- not by
     * scanning for a second delimiter -- so this is safe even if content
     * itself contains '\n' bytes. */
    size_t content_len = strlen(content);
    char header[MAX_LINE];
    int hn = snprintf(header, sizeof(header), "OK READ %s %zu\n", path, content_len);
    if (hn < 0 || (size_t)hn >= sizeof(header)) return;
    size_t total = (size_t)hn + content_len;
    char *frame = malloc(total);
    if (!frame) return;
    memcpy(frame, header, (size_t)hn);
    memcpy(frame + hn, content, content_len);
    send_frame(fd, frame, total);
    free(frame);
}

static void handle_list(int fd) {
    if (g_cfg.locked) {
        send_textf(fd, "ERR LOCKED");
        return;
    }
    /* "OK LIST <n>\npath1\npath2\n...\npathn", one frame, no trailing '\n'
     * (the frame length itself marks the end -- no delimiter needed). */
    char buf[MAX_LINE];
    int len = snprintf(buf, sizeof(buf), "OK LIST %d", g_file_count);
    if (len < 0) return;
    for (int i = 0; i < g_file_count && (size_t)len < sizeof(buf); i++) {
        int n = snprintf(buf + len, sizeof(buf) - (size_t)len, "\n%s", g_files[i].path);
        if (n < 0) return;
        len += n;
    }
    if ((size_t)len >= sizeof(buf)) len = (int)sizeof(buf) - 1; /* truncate defensively */
    send_frame(fd, buf, (size_t)len);
}

static void handle_connection(int fd) {
    /* per-connection state is derived from g_cfg but locked resets per run
     * so each attack attempt starts from a clean device state */
    g_cfg.locked = 1;

    char *payload;
    ssize_t plen;
    while ((plen = read_frame(fd, &payload)) > 0) {
        char cmd[32] = {0};
        char arg[MAX_LINE] = {0};
        sscanf(payload, "%31s %4000[^\n]", cmd, arg);
        free(payload);

        if (strcmp(cmd, "HELLO") == 0) {
            handle_hello(fd);
        } else if (strcmp(cmd, "STAGE") == 0) {
            int stage_id = atoi(arg);
            if (g_cfg.drop_at_stage == stage_id) {
                fprintf(stderr, "[sim] dropping connection at stage %d\n", stage_id);
                close(fd);
                return;
            }
            handle_stage(fd, stage_id);
        } else if (strcmp(cmd, "UNLOCK") == 0) {
            handle_unlock(fd);
        } else if (strcmp(cmd, "READ") == 0) {
            handle_read(fd, arg);
        } else if (strcmp(cmd, "LIST") == 0) {
            handle_list(fd);
        } else if (strcmp(cmd, "QUIT") == 0) {
            send_textf(fd, "OK BYE");
            break;
        } else {
            send_textf(fd, "ERR UNKNOWN %s", cmd);
        }
    }
    close(fd);
}

static void parse_args(int argc, char **argv) {
    strcpy(g_cfg.model, "iPhone12,1");
    strcpy(g_cfg.ios_version, "14.4");
    g_cfg.battery = 80;
    g_cfg.locked = 1;
    g_cfg.fail_stage_count = 0;
    g_cfg.drop_at_stage = -1;
    g_cfg.seed = 42;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            strncpy(g_cfg.model, argv[++i], sizeof(g_cfg.model) - 1);
        } else if (strcmp(argv[i], "--ios") == 0 && i + 1 < argc) {
            strncpy(g_cfg.ios_version, argv[++i], sizeof(g_cfg.ios_version) - 1);
        } else if (strcmp(argv[i], "--battery") == 0 && i + 1 < argc) {
            g_cfg.battery = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fail-stage") == 0 && i + 1 < argc) {
            if (g_cfg.fail_stage_count < MAX_FAIL_STAGES) {
                g_cfg.fail_stages[g_cfg.fail_stage_count++] = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--drop-stage") == 0 && i + 1 < argc) {
            g_cfg.drop_at_stage = atoi(argv[++i]);
        }
    }
}

int main(int argc, char **argv) {
    int port = 9000;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = atoi(argv[++i]);
        }
    }
    parse_args(argc, argv);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(server_fd, 8) < 0) {
        perror("listen");
        return 1;
    }

    fprintf(stderr, "[sim] listening on port %d (model=%s ios=%s battery=%d)\n",
            port, g_cfg.model, g_cfg.ios_version, g_cfg.battery);
    fflush(stderr);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        handle_connection(client_fd);
    }

    close(server_fd);
    return 0;
}
