/*
 * Device simulator.
 *
 * Speaks a small line-based text protocol over TCP (see PROTOCOL.md) and
 * stands in for a real mobile device: it exposes device info, "runs" attack
 * stages with configurable success/failure, and once "unlocked" serves reads
 * from a tiny in-memory filesystem. It can also simulate a connection that
 * drops mid-chain, which is the main failure mode the orchestrator has to
 * handle gracefully.
 *
 * One client is served at a time (accept -> handle to completion -> accept
 * next). That's enough for an orchestrator that runs one attack at a time,
 * and it keeps the state machine trivial to reason about.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_LINE 4096
#define MAX_FAIL_STAGES 64
#define MAX_FILES 32

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

static void send_line(int fd, const char *fmt, ...) {
    char buf[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf) - 2, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    buf[n++] = '\n';
    buf[n] = '\0';
    /* best-effort write; a broken pipe here just means the client dropped */
    write(fd, buf, n);
}

/* Reads a single '\n'-terminated line. Returns line length, 0 on clean EOF,
 * -1 on error/oversized line. */
static int read_line(int fd, char *out, size_t out_size) {
    size_t len = 0;
    while (len + 1 < out_size) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == 0) return (len == 0) ? 0 : (int)len; /* EOF */
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (c == '\n') {
            out[len] = '\0';
            return (int)len;
        }
        if (c != '\r') out[len++] = c;
    }
    return -1; /* line too long */
}

static void handle_hello(int fd) {
    send_line(fd, "OK HELLO model=%s ios=%s battery=%d locked=%d",
               g_cfg.model, g_cfg.ios_version, g_cfg.battery, g_cfg.locked);
}

static void handle_stage(int fd, int stage_id) {
    /* NOTE: connection-drop for this stage is handled by the caller
     * (handle_connection) before we get here, since dropping means we must
     * not send any response at all. */
    if (should_fail_stage(stage_id)) {
        send_line(fd, "OK STAGE %d FAIL", stage_id);
        return;
    }
    send_line(fd, "OK STAGE %d SUCCESS", stage_id);
}

static void handle_unlock(int fd) {
    g_cfg.locked = 0;
    send_line(fd, "OK UNLOCK locked=%d", g_cfg.locked);
}

static void handle_read(int fd, const char *path) {
    if (g_cfg.locked) {
        send_line(fd, "ERR LOCKED");
        return;
    }
    const char *content = find_file(path);
    if (!content) {
        send_line(fd, "ERR NOTFOUND %s", path);
        return;
    }
    send_line(fd, "OK READ %s %zu", path, strlen(content));
    /* raw payload, not newline-delimited, so binary-ish content is safe */
    write(fd, content, strlen(content));
    write(fd, "\n", 1);
}

static void handle_list(int fd) {
    if (g_cfg.locked) {
        send_line(fd, "ERR LOCKED");
        return;
    }
    send_line(fd, "OK LIST %d", g_file_count);
    for (int i = 0; i < g_file_count; i++) {
        send_line(fd, "%s", g_files[i].path);
    }
}

static void handle_connection(int fd) {
    char line[MAX_LINE];
    int n;
    /* per-connection state is derived from g_cfg but locked resets per run
     * so each attack attempt starts from a clean device state */
    g_cfg.locked = 1;

    while ((n = read_line(fd, line, sizeof(line))) > 0) {
        char cmd[32] = {0};
        char arg[MAX_LINE] = {0};
        sscanf(line, "%31s %4000[^\n]", cmd, arg);

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
            send_line(fd, "OK BYE");
            break;
        } else {
            send_line(fd, "ERR UNKNOWN %s", cmd);
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
