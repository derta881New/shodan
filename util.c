#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "headers/includes.h"
#include "headers/util.h"

ipv4_t LOCAL_ADDR = 0;

ipv4_t util_local_addr(void) {
    struct ifaddrs *ifaddrs_ptr = NULL;
    struct ifaddrs *ifa = NULL;
    ipv4_t addr = 0;
    
    if (getifaddrs(&ifaddrs_ptr) == -1) {
        return INET_ADDR(127, 0, 0, 1);
    }
    
    for (ifa = ifaddrs_ptr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa_in = (struct sockaddr_in *)ifa->ifa_addr;
            uint32_t ip = sa_in->sin_addr.s_addr;
            
            if (ip != INET_ADDR(127, 0, 0, 1) && 
                strncmp(ifa->ifa_name, "lo", 2) != 0) {
                addr = ip;
                break;
            }
        }
    }
    
    if (ifaddrs_ptr) {
        freeifaddrs(ifaddrs_ptr);
    }
    
    return addr != 0 ? addr : INET_ADDR(192, 168, 1, 100);
}

int util_strlen(char *str) {
    return strlen(str);
}

void util_zero(void *buf, int len) {
    memset(buf, 0, len);
}