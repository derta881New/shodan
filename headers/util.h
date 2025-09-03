#pragma once

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

ipv4_t util_local_addr(void);
int util_strlen(char *str);
void util_zero(void *buf, int len);