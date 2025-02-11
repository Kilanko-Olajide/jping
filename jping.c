
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <netdb.h>


unsigned short in_cksum(unsigned short *data, int length) {
    unsigned int sum = 0;

    while (length > 1) {
        sum += *data++;
        length -= 2;
    }


    if (length == 1) {
        sum += *(unsigned char *)data;
    }


    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (unsigned short)(~sum);
}


void usage(const char *progname) {
    printf("Usage: %s <target IP>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        usage(argv[0]);
    }



    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd == -1) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    char ip_address[100];
    struct hostent *ip_info;
    struct in_addr *ex_ip_address;


    if ((ip_info = gethostbyname(argv[1])) == NULL) {
        strcpy(ip_address, argv[1]);
    }
    else {
        ex_ip_address = (struct in_addr *) (ip_info->h_addr_list[0]);
        strcpy(ip_address, inet_ntoa(*ex_ip_address));
    }

    ip_address[strlen(ip_address)] = 0;


    struct sockaddr_in target_addr;
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_address, &target_addr.sin_addr) != 1) {
        fprintf(stderr, "IP address Error: %s\n", argv[1]);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char packet[1024];  

    struct icmphdr *icmp_hdr = (struct icmphdr *) packet;
    icmp_hdr->type = ICMP_ECHO;    
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = htons(getpid() & 0XFFFF);
    icmp_hdr->un.echo.sequence = htons(1);

    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = in_cksum((unsigned short *) packet, sizeof(packet));



    if ((sendto(sockfd, packet, sizeof(packet), 0,(struct sockaddr *)&target_addr, sizeof(target_addr))) == -1) {
        perror("sendto");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Sent ICMP echo request to %s\n", argv[1]);


    struct timeval timeout = {3, 0};

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == -1) {
        perror("setsockopt timeout");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    char recv_buf[1024];
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);

    if ((recvfrom(sockfd, &recv_buf, sizeof(recv_buf), 0,(struct sockaddr *)&recv_addr, &addr_len)) == -1) {
        perror("recv_from");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct iphdr *ip_hdr;
    ip_hdr = (struct iphdr *) recv_buf;
    struct icmphdr *recv_icmp_hdr;
    recv_icmp_hdr = (struct icmphdr *)(recv_buf + sizeof(struct iphdr));

    if (recv_icmp_hdr->type == ICMP_ECHOREPLY) {
        printf("Looks like the host is online\n");
        printf("Received ICMP echo reply from %s\n", argv[1]);
        printf("IP_ADDRESS: %s\n", ip_address);
        printf("Packet received(Sequence: %d, Identification: %d, ttl: %d, total_length: %d)\n", ntohs(recv_icmp_hdr->un.echo.sequence), ip_hdr->id,  ip_hdr->ttl, ip_hdr->tot_len);
    } else {
        printf("Received unexpected ICMP packet. Type: %d\n", recv_icmp_hdr->type);
    }

    close(sockfd);
    return 0;
}
