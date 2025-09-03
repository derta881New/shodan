#pragma once

#include <stdint.h>

uint16_t checksum_generic(uint16_t *addr, uint32_t count);
uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len);