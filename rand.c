#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "headers/rand.h"

static uint32_t x = 0, y = 0, z = 0, w = 0;

void rand_init(void) {
    int fd;
    
    if ((fd = open("/dev/urandom", O_RDONLY)) != -1) {
        read(fd, &x, 4);
        read(fd, &y, 4);
        read(fd, &z, 4);  
        read(fd, &w, 4);
        close(fd);
    } else {
        x = time(NULL);
        y = getpid() ^ x;
        z = clock() ^ y;
        w = x ^ y ^ z;
    }
}

uint32_t rand_next(void) {
    uint32_t t = x;
    t ^= x << 11;
    t ^= t >> 8;
    x = y;
    y = z;
    z = w;
    w ^= w >> 19;
    w ^= t;
    return w;
}