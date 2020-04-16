#include <sys/time.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <unistd.h>


#define KYEL  "\x1B[33m"
#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"

#define INTERVAL 1000000
#define TIMEOUT 1
#define PACKET_SIZE 64

int ping_loop = 1;


struct ping_packet {
	struct icmphdr header; 
	char msg[PACKET_SIZE-sizeof(struct icmphdr)]; 
};

struct stats {
	int pkt_sent_cnt;
	int pkt_recv_cnt;
	float min_rtt;
	float max_rtt;
	float sum_rtt;
};

struct options {
	int ttl;
	int count;
	int interval;
	int timeout;
};

char* get_hostname_addr(char* address)
{
	struct hostent* h;
	h = gethostbyname(address);
	if (h == NULL) 
	{
		printf("invalid destination %s\n", address);
		exit(EXIT_FAILURE);
	}
	return inet_ntoa(*(struct in_addr *)h->h_addr);
}

int create_socket(int ttl, int ts) 
{
	struct timeval timeout; 
	timeout.tv_sec = ts; 
	timeout.tv_usec = 0; 

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)); 
	setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
	return sockfd;
}

int is_valid_ip(char *ip_addr) 
{
	struct sockaddr_in sa;
	return inet_pton(AF_INET, ip_addr, &(sa.sin_addr));
}

void show_usage() 
{
	printf("%s", KGRN);
	printf("Usage: ping [-t ttl] [-c count] [-i interval] [-w timeout] destination\n");
	printf("%s", KNRM);
}

void interrupt_handler(int sig) 
{
	ping_loop = 0;
}

void show_stats(struct stats* statistics)
{
	float avg_rtt = statistics->sum_rtt/(float)statistics->pkt_recv_cnt;
	if (statistics->pkt_recv_cnt == 0)
	{
		statistics->min_rtt = 0;
		statistics->max_rtt = 0;
		statistics->sum_rtt = 0;
		avg_rtt = 0;
	}
	float pkt_loss = ((statistics->pkt_sent_cnt - statistics->pkt_recv_cnt)/(float)statistics->pkt_sent_cnt)*100.0;
	printf("\n%s", KGRN);
	printf("+-----------------------------------------+\n");
	printf("+----------------- STATS -----------------+\n");
	printf("+-----------------------------------------+\n");
	printf("%s", KNRM);
	printf("%d packets transmitted, %d received, %.2f%% packet loss\n", statistics->pkt_sent_cnt, statistics->pkt_recv_cnt, pkt_loss);
	printf("min rtt: %.2f ms, max rtt: %.2f ms, avg rtt: %.2f ms \n", statistics->min_rtt, statistics->max_rtt, avg_rtt);
}

unsigned short checksum(unsigned short *buffer, int len) 
{    
	unsigned long cksum = 0; 
	for (cksum = 0; len > 1; len -= 2 )
	{
		cksum += *buffer++;
	}
	if (len == 1) 
	{
		cksum += *(unsigned char*)buffer; 
	}
	cksum = (cksum >> 16) + (cksum & 0xFFFF); 
	cksum += (cksum >> 16);
	return ~cksum; 
}

struct ping_packet* init_ping_pkt(struct ping_packet* packet, int seq_no) 
{
	int i;
	bzero(packet, sizeof(struct ping_packet)); 
	for ( i = 0; i < sizeof(packet->msg)-1; i++) 
		packet->msg[i] = i+'0';
	packet->msg[i] = 0; 
	packet->header.code = 0;
	packet->header.type = ICMP_ECHO;
	packet->header.un.echo.id = getpid();
	packet->header.un.echo.sequence = seq_no;
	packet->header.checksum = checksum((unsigned short*)packet, sizeof(struct ping_packet));
	return packet;
}

float ping(int sockfd, struct sockaddr_in* connection, char* destination, struct stats* statistics)
{
	struct timeval start, end;
	struct iphdr* ip_reply;
	struct ping_packet* packet; 
	struct ping_packet* reply_packet;
	struct sockaddr_in reply_addr; 
	char* in_pkt;
	int addrlen;
	float rtt;
	int recv_bytes;

	packet = (struct ping_packet*)malloc(sizeof(struct ping_packet));
	in_pkt = malloc(sizeof(struct iphdr) + sizeof(struct ping_packet));
	init_ping_pkt(packet, statistics->pkt_sent_cnt);

	gettimeofday(&start, NULL);
	sendto(sockfd, packet, sizeof(struct ping_packet), 0, (struct sockaddr *)connection, sizeof(*connection));

	statistics->pkt_sent_cnt++;

	addrlen = sizeof(reply_addr);
	if((recv_bytes = recvfrom(sockfd, in_pkt, sizeof(struct iphdr) + sizeof(struct ping_packet), 0, (struct sockaddr *)&reply_addr, &addrlen)) == -1) 
	{
		perror("recv");
	} else 
	{
		ip_reply = (struct iphdr*) in_pkt;
		reply_packet = (struct ping_packet*)(in_pkt + sizeof(struct iphdr));
		// printf("type: %d, code: %d\n", reply_packet->header.type, reply_packet->header.code);
		if (reply_packet->header.type == ICMP_TIME_EXCEEDED) 
		{
			printf("%d bytes from (%s%s%s) time: %sTime to live exceeded%s\n", recv_bytes, KYEL, destination, KNRM, KRED, KNRM);
		} else if (reply_packet->header.type == ICMP_ECHOREPLY) 
		{
			gettimeofday(&end, NULL);
			rtt = 1000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000.0;
			statistics->pkt_recv_cnt++;
			printf("%d bytes from (%s%s%s) time: %s%.2f%s ms\n", recv_bytes, KYEL, destination, KNRM, KGRN, rtt, KNRM);
		}
	}

	free(packet);
	free(in_pkt);
	return rtt;
}

void send_ping_requests(char* destination, struct options* opts)
{
	struct stats statistics = {0, 0, 10, -1, 0};
	struct sockaddr_in connection;

	if (is_valid_ip(destination) != 1) 
	{
		destination = get_hostname_addr(destination);
	}

	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = inet_addr(destination);

	int sockfd = create_socket(opts->ttl, opts->timeout);

	printf("%s", KYEL);
	printf("PING (%s)\n", destination);
	printf("%s", KNRM);
	while (ping_loop) {
		if (opts->count > 0)
		{
			opts->count--;
		} else if (opts->count == 0) 
		{
			ping_loop = 0;
			break;
		}

		float rtt = ping(sockfd, &connection, destination, &statistics);
		statistics.sum_rtt += rtt;
		if (rtt > statistics.max_rtt)
			statistics.max_rtt = rtt;
		if (rtt < statistics.min_rtt)
			statistics.min_rtt = rtt;
		usleep(opts->interval);
	}
	close(sockfd);
	show_stats(&statistics);
}


int main(int argc, char** argv) { 
	int opt;
	struct options opts = {64, -1, INTERVAL, TIMEOUT};

	if (argc % 2 == 1 || argc < 2) {
		show_usage();
		return 0;
	}

	while((opt = getopt(argc, argv, "t:c:i:w:")) != -1)  
	{  
		switch(opt)  
		{  
			case 't': 
				opts.ttl = atoi(optarg);
				break;  
			case 'c':
				opts.count = atoi(optarg);
				break;
			case 'i':
				opts.interval = atoi(optarg) * 1000000;
				break;
			case 'w':
				opts.timeout = atoi(optarg);
				break;  
			case ':':  
				printf("option needs a value\n");  
				break;  
			case '?':
				if (optopt == 'c')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 't')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'i')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt);
				else if (optopt == 'w')
					fprintf (stderr, "Option -%c requires an argument.\n", optopt); 				
			break;  
		}  
	}

	signal(SIGINT, interrupt_handler);

	if(getuid() != 0)
	{
		// raw socket requires sudo 
		fprintf(stderr, "%s: root privileges needed\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	send_ping_requests(argv[argc -1], &opts);

	return 0;
}