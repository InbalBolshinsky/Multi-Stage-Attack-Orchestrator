/*
 * Device simulator.
 *
 * Stands in for a real mobile device over TCP: reports device info, "runs"
 * attack stages with configurable success/failure, and once "unlocked"
 * serves reads from a small in-memory filesystem. Can also simulate a
 * silent connection drop (--drop-stage) or a device crash (--crash-stage).
 *
 * Every message is [4-byte length][payload], so payload content (like a
 * file's bytes) can safely contain '\n' or anything else.
 *
 * Handles one client at a time, which is all an orchestrator running one
 * attack at a time needs.
 */

//Includes and constants:
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

#define MAX_LINE 4096 // One page memory round arbitrary number
#define MAX_FAIL_STAGES 64 // A big enough number for 3-6 flags (e.g. "--fail-stage")
/* Sanity bound on an incoming frame's declared length. This is untrusted
 * input, so we bound it instead of trusting the 4-byte length prefix to
 * malloc() whatever it claims. Real payloads here are at most a few
 * hundred bytes, so 64 KiB is already generous headroom. */
#define MAX_FRAME (64 * 1024)

/* command[]/arg[] in handle_connection are parsed with sscanf field
 * widths that must leave room for the NUL terminator. Building the
 * format string from these macros, checked by the _Static_assert below,
 * keeps the width and buffer size from silently drifting apart. */
#define COMMAND_BUF_SIZE 32
#define COMMAND_SCAN_WIDTH 31
#define ARG_SCAN_WIDTH 4000
_Static_assert(COMMAND_SCAN_WIDTH == COMMAND_BUF_SIZE - 1,
               "COMMAND_SCAN_WIDTH must be COMMAND_BUF_SIZE - 1 (room for the NUL)");
_Static_assert(ARG_SCAN_WIDTH < MAX_LINE,
               "ARG_SCAN_WIDTH must leave room for the NUL terminator in arg[MAX_LINE]");

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

// Defining the mock filesystem:
typedef struct {
    const char *path;
    const char *content;
} FakeFile;

/* Default fake filesystem, kept small and readable. g_file_count is
 * derived from g_files' size, so it can't drift out of sync when an
 * entry is added or removed. */
static FakeFile g_files[] = {
    {"/var/mobile/Library/db/contacts.db", "CONTACTS_DB_BINARY_BLOB_PLACEHOLDER"},
    {"/var/mobile/Library/db/messages.db", "MESSAGES_DB_BINARY_BLOB_PLACEHOLDER"},
    {"/var/mobile/Media/DCIM/100APPLE/IMG_0001.JPG", "JPEG_BYTES_PLACEHOLDER_1"},
    {"/var/mobile/Media/DCIM/100APPLE/IMG_0002.JPG", "JPEG_BYTES_PLACEHOLDER_2"},
    {"/var/mobile/Library/Notes/notes.sqlite", "NOTES_DB_BINARY_BLOB_PLACEHOLDER"},
};
static const int g_file_count = (int)(sizeof(g_files) / sizeof(g_files[0]));

// Device state
typedef struct {
    char model[64];
    char ios_version[16];
    int battery;      /* 0-100 */
    int locked;       /* 1 = locked, 0 = unlocked */
    int after_first_unlock; /* 1 = AFU (passcode entered since last boot), 0 = BFU */
    int jailbroken;         /* 1 = device already has a working jailbreak, 0 = stock */
    int fail_stages[MAX_FAIL_STAGES];
    int fail_stage_count;
    int drop_at_stage;  /* stage id at which to silently close the connection; -1 = never */
    int crash_at_stage; /* stage id at which to send ERR CRASH, then close; -1 = never */
} DeviceConfig;

static DeviceConfig g_device;

// Helper functions:
static int should_fail_stage(int stage_id) {
    for (int i = 0; i < g_device.fail_stage_count; i++) {
        if (g_device.fail_stages[i] == stage_id) return 1;
    }
    return 0;
}

static const char *find_file_content(const char *path) {
    for (int i = 0; i < g_file_count; i++) {
        if (strcmp(g_files[i].path, path) == 0) return g_files[i].content;
    }
    return NULL;
}

// Reading and writing the bytes:
/* Reads exactly n bytes into buf, looping over short reads. Returns n on
 * success, 0 on a clean close between frames, -1 on error or a partial
 * frame (both treated as a dropped connection). */
static ssize_t read_exact(int fd, void *buf, size_t len) {
    size_t bytes_read = 0;
    while (bytes_read < len) {
        ssize_t n = read(fd, (char *)buf + bytes_read, len - bytes_read);
        if (n == 0) return (bytes_read == 0) ? 0 : -1;
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        bytes_read += (size_t)n;
    }
    return (ssize_t)bytes_read;
}

/* Writes exactly len bytes, looping over short writes. Best-effort: a
 * broken pipe here just means the client dropped. */
static int write_exact(int fd, const void *buf, size_t len) {
    size_t bytes_written = 0;
    while (bytes_written < len) {
        ssize_t n = write(fd, (const char *)buf + bytes_written, len - bytes_written);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        bytes_written += (size_t)n;
    }
    return 0;
}

// Sending the frame:
static int send_frame(int fd, const void *payload, size_t len) {
    uint32_t len_be = htonl((uint32_t)len);
    if (write_exact(fd, &len_be, sizeof(len_be)) < 0) return -1;
    if (len > 0 && write_exact(fd, payload, len) < 0) return -1;
    return 0;
}

/* Formats a text payload and sends it as one frame. No trailing '\n',
 * that was only needed for the old line-delimited framing. */
static void send_textf(int fd, const char *fmt, ...) {
    char buf[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int text_len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (text_len < 0) return;
    if ((size_t)text_len >= sizeof(buf)) text_len = (int)sizeof(buf) - 1; /* truncate defensively */
    send_frame(fd, buf, (size_t)text_len);
}


// Reading the frame:
/* Reads one length-prefixed frame into a heap buffer the caller must
 * free(). *out_payload is NUL-terminated for easy text parsing. Returns
 * the payload length on success, 0 on a clean close at a frame boundary,
 * -1 on error, an oversized length, a partial frame, or a zero-length
 * frame (no real command is ever empty). *out_payload is only set on the
 * >0 path, so the caller always has exactly one buffer to free. */
static ssize_t read_frame(int fd, char **out_payload) {
    uint32_t len_be;
    ssize_t header_result = read_exact(fd, &len_be, sizeof(len_be));

    if (header_result <= 0) return header_result;

    uint32_t payload_len = ntohl(len_be);

    if (payload_len == 0 || payload_len > MAX_FRAME) return -1;

    char *payload = malloc((size_t)payload_len + 1);

    if (!payload) return -1;

    ssize_t body_result = read_exact(fd, payload, payload_len);

    if (body_result <= 0) { free(payload); return -1; } /* any EOF here is mid-frame */
    
    payload[payload_len] = '\0';
    *out_payload = payload;

    return (ssize_t)payload_len;
}

//Command handlers:
static void handle_hello(int client_fd) {
    send_textf(client_fd, "OK HELLO model=%s ios=%s battery=%d locked=%d afu=%d jailbroken=%d",
               g_device.model, g_device.ios_version, g_device.battery, g_device.locked,
               g_device.after_first_unlock, g_device.jailbroken);
}

static void handle_stage(int client_fd, int stage_id) {
    /* NOTE: connection-drop for this stage is handled by the caller
     * (handle_connection) before we get here, since dropping means we must
     * not send any response at all. */
    if (should_fail_stage(stage_id)) {
        send_textf(client_fd, "OK STAGE %d FAIL", stage_id);
        return;
    }
    send_textf(client_fd, "OK STAGE %d SUCCESS", stage_id);
}

static void handle_unlock(int client_fd) {
    g_device.locked = 0;
    send_textf(client_fd, "OK UNLOCK locked=%d", g_device.locked);
}

static void handle_read(int client_fd, const char *path) {
    if (g_device.locked) {
        send_textf(client_fd, "ERR LOCKED");
        return;
    }
    const char *content = find_file_content(path);
    if (!content) {
        send_textf(client_fd, "ERR NOTFOUND %s", path);
        return;
    }
    /* One frame: a text header, then '\n', then the raw file bytes.
     * The receiver splits on the first '\n' only, then takes the rest
     * by length. */
    size_t content_len = strlen(content);
    char header[MAX_LINE];
    int header_len = snprintf(header, sizeof(header), "OK READ %s %zu\n", path, content_len);
    if (header_len < 0 || (size_t)header_len >= sizeof(header)) return;
    size_t frame_len = (size_t)header_len + content_len;
    char *frame = malloc(frame_len);
    if (!frame) return;
    memcpy(frame, header, (size_t)header_len);
    memcpy(frame + header_len, content, content_len);
    send_frame(client_fd, frame, frame_len);
    free(frame);
}

static void handle_list(int client_fd) {
    if (g_device.locked) {
        send_textf(client_fd, "ERR LOCKED");
        return;
    }
    /* "OK LIST <n>\npath1\npath2\n...\npathn", one frame, no trailing '\n'. */
    char response[MAX_LINE];
    int response_len = snprintf(response, sizeof(response), "OK LIST %d", g_file_count);
    if (response_len < 0) return;
    for (int i = 0; i < g_file_count && (size_t)response_len < sizeof(response); i++) {
        int line_len = snprintf(response + response_len, sizeof(response) - (size_t)response_len,
                                 "\n%s", g_files[i].path);
        if (line_len < 0) return;
        response_len += line_len;
    }
    if ((size_t)response_len >= sizeof(response)) response_len = (int)sizeof(response) - 1; /* truncate defensively */
    send_frame(client_fd, response, (size_t)response_len);
}

// Connection loop handler:
static void handle_connection(int client_fd) {
    /* per-connection state is derived from g_device but locked resets per
     * run so each attack attempt starts from a clean device state */
    g_device.locked = 1;

    char *payload;
    ssize_t payload_len;
    while ((payload_len = read_frame(client_fd, &payload)) > 0) {
        char command[COMMAND_BUF_SIZE] = {0};
        char arg[MAX_LINE] = {0};
        sscanf(payload, "%" STRINGIFY(COMMAND_SCAN_WIDTH) "s %" STRINGIFY(ARG_SCAN_WIDTH) "[^\n]",
               command, arg);
        free(payload);

        if (strcmp(command, "HELLO") == 0) {
            handle_hello(client_fd);
        } else if (strcmp(command, "STAGE") == 0) {
            int stage_id = atoi(arg);
            if (g_device.crash_at_stage == stage_id) {
                fprintf(stderr, "[sim] device crash at stage %d\n", stage_id);
                send_textf(client_fd, "ERR CRASH %d", stage_id);
                close(client_fd);
                return;
            }
            if (g_device.drop_at_stage == stage_id) {
                fprintf(stderr, "[sim] dropping connection at stage %d\n", stage_id);
                close(client_fd);
                return;
            }
            handle_stage(client_fd, stage_id);
        } else if (strcmp(command, "UNLOCK") == 0) {
            handle_unlock(client_fd);
        } else if (strcmp(command, "READ") == 0) {
            handle_read(client_fd, arg);
        } else if (strcmp(command, "LIST") == 0) {
            handle_list(client_fd);
        } else if (strcmp(command, "QUIT") == 0) {
            send_textf(client_fd, "OK BYE");
            break;
        } else {
            send_textf(client_fd, "ERR UNKNOWN %s", command);
        }
    }
    close(client_fd);
}

// Command line parser:
static void parse_args(int argc, char **argv) {
    strcpy(g_device.model, "iPhone12,1");
    strcpy(g_device.ios_version, "14.4");
    g_device.battery = 80;
    g_device.locked = 1;
    g_device.after_first_unlock = 1; /* AFU by default (BFU is the rarer opt-in case) */
    g_device.jailbroken = 0;         /* stock by default (jailbroken is the opt-in case) */
    g_device.fail_stage_count = 0;
    g_device.drop_at_stage = -1;
    g_device.crash_at_stage = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--model") == 0 && i + 1 < argc) {
            strncpy(g_device.model, argv[++i], sizeof(g_device.model) - 1);
        } else if (strcmp(argv[i], "--ios") == 0 && i + 1 < argc) {
            strncpy(g_device.ios_version, argv[++i], sizeof(g_device.ios_version) - 1);
        } else if (strcmp(argv[i], "--battery") == 0 && i + 1 < argc) {
            g_device.battery = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fail-stage") == 0 && i + 1 < argc) {
            if (g_device.fail_stage_count < MAX_FAIL_STAGES) {
                g_device.fail_stages[g_device.fail_stage_count++] = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--drop-stage") == 0 && i + 1 < argc) {
            g_device.drop_at_stage = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--crash-stage") == 0 && i + 1 < argc) {
            g_device.crash_at_stage = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--bfu") == 0) {
            g_device.after_first_unlock = 0;
        } else if (strcmp(argv[i], "--jailbroken") == 0) {
            g_device.jailbroken = 1;
        }
    }
}

// Main:
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

    int reuse_addr = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

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

    fprintf(stderr, "[sim] listening on port %d (model=%s ios=%s battery=%d afu=%d jailbroken=%d)\n",
            port, g_device.model, g_device.ios_version, g_device.battery,
            g_device.after_first_unlock, g_device.jailbroken);
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
