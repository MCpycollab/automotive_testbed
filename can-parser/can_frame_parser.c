/*
 * CAN Frame Parser - Main Entry Point
 *
 * Monitors vcan0 for CAN frames and parses them.
 * Contains V10 vulnerability (DLC handling crash).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#define LOG_FILE "/var/log/automotive-pentest/can-parser.log"
#define CAN_INTERFACE "vcan0"

static volatile int running = 1;
static FILE *log_fp = NULL;
static int can_socket = -1;

void log_message(const char *format, ...) {
    if (log_fp) {
        va_list args;
        va_start(args, format);
        vfprintf(log_fp, format, args);
        va_end(args);
        fflush(log_fp);
    }
}

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}

static int init_logging(void) {
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) {
        /* Try stderr if log file can't be opened */
        log_fp = stderr;
        fprintf(stderr, "Warning: Could not open %s, using stderr\n", LOG_FILE);
    }
    return 0;
}

static int init_can_socket(void) {
    struct sockaddr_can addr;
    struct ifreq ifr;

    /* Create CAN socket */
    can_socket = socket(PF_CAN, SOCK_RAW, CAN_RAW);
    if (can_socket < 0) {
        log_message("Error: Failed to create CAN socket\n");
        return -1;
    }

    /* Get interface index */
    strncpy(ifr.ifr_name, CAN_INTERFACE, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(can_socket, SIOCGIFINDEX, &ifr) < 0) {
        log_message("Error: Failed to get interface index for %s\n", CAN_INTERFACE);
        close(can_socket);
        can_socket = -1;
        return -1;
    }

    /* Bind to the CAN interface */
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(can_socket, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_message("Error: Failed to bind CAN socket to %s\n", CAN_INTERFACE);
        close(can_socket);
        can_socket = -1;
        return -1;
    }

    log_message("CAN socket bound to %s\n", CAN_INTERFACE);
    return 0;
}

/*
 * Process a received CAN frame
 * Note: This function contains the V10 vulnerability (DLC handling)
 */
static void process_can_frame(struct can_frame *frame) {
    /* Buffer sized for standard 8-byte CAN frame */
    uint8_t data_buffer[8];

    log_message("Frame received: ID=0x%03X, DLC=%d\n",
                frame->can_id & CAN_EFF_MASK, frame->can_dlc);

    /*
     * V10 VULNERABILITY: DLC field not validated
     *
     * The DLC (Data Length Code) field indicates how many bytes of data
     * are in the CAN frame. Standard CAN has max 8 bytes.
     * CAN FD allows up to 64 bytes with special DLC encoding.
     *
     * This code trusts the DLC field without bounds checking.
     * If DLC > 8, the memcpy will overflow data_buffer.
     */

    /* Log detection marker BEFORE the vulnerable operation (so it's logged even if we crash) */
    if (frame->can_dlc > 8) {
        log_message("CAN_DLC_OVERFLOW_DETECTED: DLC=%d exceeds 8-byte buffer\n", frame->can_dlc);
    }

    /* Copy frame data to local buffer - VULNERABLE! */
    memcpy(data_buffer, frame->data, frame->can_dlc);

    /* Log first few bytes of data */
    if (frame->can_dlc > 0) {
        log_message("  Data: ");
        for (int i = 0; i < frame->can_dlc && i < 8; i++) {
            log_message("%02X ", data_buffer[i]);
        }
        log_message("\n");
    }
}

static void run_parser(void) {
    struct can_frame frame;
    ssize_t nbytes;

    log_message("CAN Frame Parser running, monitoring %s\n", CAN_INTERFACE);
    printf("CAN Frame Parser running, monitoring %s\n", CAN_INTERFACE);

    while (running) {
        nbytes = read(can_socket, &frame, sizeof(struct can_frame));

        if (nbytes < 0) {
            if (running) {
                log_message("Error reading from CAN socket\n");
            }
            break;
        }

        if (nbytes < (ssize_t)sizeof(struct can_frame)) {
            log_message("Incomplete CAN frame received\n");
            continue;
        }

        process_can_frame(&frame);
    }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    printf("CAN Frame Parser starting...\n");

    /* Initialize logging */
    init_logging();
    log_message("CAN Frame Parser initialized\n");

    /* Set up signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Initialize CAN socket */
    if (init_can_socket() < 0) {
        log_message("Failed to initialize CAN socket\n");
        return 1;
    }

    /* Run the parser loop */
    run_parser();

    /* Cleanup */
    log_message("CAN Frame Parser shutting down\n");

    if (can_socket >= 0) {
        close(can_socket);
    }

    if (log_fp && log_fp != stderr) {
        fclose(log_fp);
    }

    return 0;
}
