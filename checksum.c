#include <stdint.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include "headers/checksum.h"

uint16_t checksum_generic(uint16_t *addr, uint32_t count) {
    register uint32_t sum = 0;
    
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    
    if (count > 0) {
        sum += ((*addr) & htons(0xFF00));
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    sum = ~sum;
    return ((uint16_t) sum);
}

uint16_t checksum_tcpudp(struct iphdr *iph, void *buff, uint16_t data_len, int len) {
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    // Make 16 bit words out of every two adjacent 8 bit words
    // Calculate the sum of all 16 bit words
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    // Add left-over byte, if any
    if (len > 0) {
        sum += ((*buf) & htons(0xFF00));
    }
    
    // Add pseudo header
    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += data_len;
    
    // Fold 32-bit sum to 16 bits: add carrier to result
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    sum = ~sum;
    return ((uint16_t) sum);
}