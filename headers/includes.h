#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define TRUE 1
#define FALSE 0

typedef uint32_t ipv4_t;
typedef uint16_t port_t;

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))

extern ipv4_t LOCAL_ADDR;