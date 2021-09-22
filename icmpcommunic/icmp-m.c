#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define IN_BUF_SIZE   1024
#define OUT_BUF_SIZE  64
#define CLINET_SEQ  4243
#define PING_SLEEP_RATE 1000000 
// calculate checksum
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    unsigned long sum;
    unsigned short oddbyte, rs;

    sum = 0;
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    rs = ~sum;
    return rs;
}



int main(int argc, char **argv){
   
    int sockfd;
    char in_buf[IN_BUF_SIZE];
    char out_buf[OUT_BUF_SIZE];
    unsigned int out_size;
    int nbytes;
    struct iphdr *ip;
    struct icmphdr *icmp;
    struct sockaddr_in addr;
 
    // create raw ICMP socket
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1) {
       perror("socket");
       return -1;
    }
    
    printf("Waiting for client to connect\n");
    int has_not_connected = 1;
    // transmission
    while(1) {
        // read data from socket
        memset(in_buf, 0x00, IN_BUF_SIZE);
        // listen for some pings
	nbytes = read(sockfd, in_buf, IN_BUF_SIZE - 1);
	if (nbytes > 0) {
            	// get ip and icmp header and data part
            	ip = (struct iphdr *) in_buf;	    
	    	if (nbytes > sizeof(struct iphdr)) {
        		nbytes -= sizeof(struct iphdr);
                	icmp = (struct icmphdr *) (ip + 1);
			// filter the correct ICMP packets -> echo request + shared secret
			if (icmp->type == 8 && icmp->un.echo.id ==  4242){
               			if (has_not_connected){ 
					printf("Client has connected\n");
					has_not_connected = 0;
				}
				// reuse headers
				out_size = 0;
	               		icmp->type = 0;
	                        icmp->code = 0;
		       	      	addr.sin_family = AF_INET;
	               	      	addr.sin_addr.s_addr = ip->saddr;
	       	       	      	icmp->un.echo.id=4242; // skip on client side
	               	      		 
		       	      	 // read data from stdin
	               	      	nbytes = read(0, out_buf, OUT_BUF_SIZE);// read the port number
	               	      	if (nbytes > -1) {
					memcpy((char*)(icmp + 1), out_buf, nbytes);
	       	       	      		icmp->un.echo.id = 4243; // to recieve on client side 
	               	      		bzero(out_buf, OUT_BUF_SIZE);
					out_size = nbytes;
					icmp->checksum = 0x00;
	               	      		icmp->checksum = checksum((unsigned short *) icmp, sizeof(struct icmphdr) + out_size);
	               	      		 // send reply
	               	      		nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + out_size, 0, (struct sockaddr *) &addr, sizeof(addr));
	               	      		if (nbytes == -1) {
	               	      			perror("sendto");
	               	      			return -1;
	               	      		}
				}
				sleep(1);
			}
		}
	}

     }
    return 0;
}
