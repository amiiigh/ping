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
#include <linux/icmp.h>
#include <string.h>
#include <unistd.h>

#define INTERVAL 1000000
#define TIMEOUT 1

int ping_loop = 1;

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

unsigned short checksum(unsigned short *buffer, int len) 
{    
	unsigned int sum=0; 
	unsigned short result; 

	for ( sum = 0; len > 1; len -= 2 )
	{
		sum += *buffer++; 
	}
	if ( len == 1 ) 
	{
		sum += *(unsigned char*)buffer; 
	}
	sum = (sum >> 16) + (sum & 0xFFFF); 
	sum += (sum >> 16); 
	result = ~sum; 
	return result; 
} 

struct icmphdr* init_icmp_hdr(char * buf, int seq_no) 
{
	struct icmphdr* icmp;
	icmp = (struct icmphdr*)(buf);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->un.echo.id = getpid();
	icmp->un.echo.sequence = seq_no;
	icmp->checksum = checksum((unsigned short *)icmp, sizeof(struct icmphdr));
	return icmp;
}

int create_socket(int ttl, int ts) 
{
	struct timeval timeout; 
	timeout.tv_sec = ts; 
	timeout.tv_usec = 0; 

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout); 
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
	printf("Usage: ping [-t ttl] [-c count] [-i interval] [-w timeout] destination\n");
}

void interrupt_handler(int sig) 
{
	ping_loop = 0;
}

void show_stats(int pkt_sent_cnt, int pkt_recv_cnt, float min_rtt, float max_rtt, float sum_rtt)
{
	float pkt_loss = ((pkt_sent_cnt - pkt_recv_cnt)/(float)pkt_sent_cnt)*100.0;
	printf("\n---- ping statistics ----\n");
	printf("%d packets transmitted, %d received, %f%% packet loss\n", pkt_sent_cnt, pkt_recv_cnt, pkt_loss);
	printf("min rtt: %f \n", min_rtt);
	printf("max rtt: %f \n", max_rtt);
	printf("avg rtt: %f \n", sum_rtt/(float)pkt_recv_cnt);
}

float ping(int sockfd, struct sockaddr_in* connection, char* destination, int* pkt_sent_cnt, int* pkt_recv_cnt)
{
	struct timeval start, end;
	struct iphdr* ip_reply;
	struct icmphdr* icmp;
	struct icmphdr* icmp_reply;
	char* out_pkt;
	char* in_pkt;
	int addrlen;
	float rtt;
	int recv_bytes;

	out_pkt = malloc(sizeof(struct icmphdr));
	in_pkt = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));

	icmp = init_icmp_hdr(out_pkt, (*pkt_sent_cnt));

	gettimeofday(&start, NULL);
	sendto(sockfd, out_pkt, sizeof(out_pkt), 0, (struct sockaddr *)connection, sizeof(*connection));
	(*pkt_sent_cnt)++;

	addrlen = sizeof(*connection);
	if((recv_bytes = recvfrom(sockfd, in_pkt, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)connection, &addrlen)) == -1) {
		perror("recv");
	} else {
		ip_reply = (struct iphdr*) in_pkt;
		icmp_reply = (struct icmphdr*)(in_pkt + sizeof(struct iphdr));
		// printf("type: %d, code: %d\n", icmp_reply->type, icmp_reply->code);
		gettimeofday(&end, NULL);
		(*pkt_recv_cnt)++;
		rtt = 1000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000.0;
		if (icmp_reply->type == 11) 
		{
			printf("Time to live exceeded\n");
		} else if (icmp_reply->type == 0) 
		{
			printf("%d bytes from (%s) time: %f ms\n", recv_bytes, destination, rtt);
		}
	}

	free(out_pkt);
	free(in_pkt);
	return rtt;
}

void send_ping_requests(char* destination, int ttl, int count, int interval, int ts)
{
	int pkt_recv_cnt = 0;
	int pkt_sent_cnt = 0;
	float max_rtt = -1;
	float min_rtt = 10000;
	float sum_rtt = 0.0;
	struct sockaddr_in connection;

	if (is_valid_ip(destination) != 1) 
	{
		destination = get_hostname_addr(destination);
	}

	connection.sin_family = AF_INET;
	connection.sin_addr.s_addr = inet_addr(destination);

	int sockfd = create_socket(ttl, ts);

	printf("PING (%s)\n", destination);
	while (ping_loop) {
		if (count > 0)
		{
			count--;
		} else if (count == 0) 
		{
			ping_loop = 0;
			break;
		}

		float rtt = ping(sockfd, &connection, destination, &pkt_sent_cnt, &pkt_recv_cnt);
		sum_rtt += rtt;
		if (rtt > max_rtt)
			max_rtt = rtt;
		if (rtt < min_rtt)
			min_rtt = rtt;
		usleep(interval);
	}
	close(sockfd);
	show_stats(pkt_sent_cnt, pkt_recv_cnt, min_rtt, max_rtt, sum_rtt);
}


int main(int argc, char** argv) { 
	if (argc % 2 == 1) {
		show_usage();
		return 0;
	}

	int opt;
	int ttl = 64;
	int count = -1;
	int interval = INTERVAL;
	int ts = TIMEOUT;
	while((opt = getopt(argc, argv, "t:c:i:w:")) != -1)  
	{  
		switch(opt)  
		{  
			case 't': 
				ttl = atoi(optarg);
				break;  
			case 'c':
				count = atoi(optarg);
				break;
			case 'i':
				interval = atoi(optarg) * 1000000;
				break;
			case 'w':
				ts = atoi(optarg);
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

	send_ping_requests(argv[argc -1], ttl, count, interval, ts);

	return 0;
}