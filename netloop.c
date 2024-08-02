#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <time.h>
#include <netinet/ether.h>
#define ERROR_BUF_MAX 1024
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
// pcap_if_t *chains=NULL;
// pcap_if_t *lassi=chains->next;
static void print_packet_info(u_char *args, struct pcap_pkthdr packet_header,const u_char *packet);
int main(int arc ,char argv[]){
pcap_t *handle;
int len = 1024;
pcap_if_t *chains=NULL;
char (*device)[123];
char error[ERROR_BUF_MAX];
device=pcap_lookupdev(error);
if (device==NULL){
printf("cant find a device %s\n",error);
return 1;
}
//printf("network devices found %s\n",device);
int exit_status;
 exit_status=pcap_findalldevs(&chains,error);
if (exit_status == EOF){
printf("not done");
return 1;
}
printf("listining on addr: %s\n",chains->name);
pcap_if_t *lassi=chains->next;
//printf("%s\n",lassi->name);
handle=pcap_open_live(device,1024,2,10000,error);
if (handle == NULL){
printf("%s",error);
}
 u_char *my_arguments = NULL;
 pcap_loop(handle, 0,print_packet_info , my_arguments);
return 0;
}
static void print_packet_info(u_char *args, struct pcap_pkthdr packet_header,const u_char *packet) {
    struct ether_header *eth_hdr;
    printf("-------------------------------------------------------------------------------------\n");

    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
    eth_hdr = (struct ether_header *) packet;
   // printf("%x",eth_hdr->ether_dhost);
    
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        printf("protocol type : IP\n");
    } else  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        printf("protocol type : ARP\n");
    } else  if (ntohs(eth_hdr->ether_type) == ETHERTYPE_REVARP) {
        printf("protocol type : Reverse ARP\n");
    }
    char *addr;
struct ether_addr host;
memcpy(&host, eth_hdr->ether_dhost, sizeof(host));
addr = (char *) ether_ntoa((struct ether_addr *) eth_hdr->ether_dhost);
printf("DESTINATION MACC ADDRESS %s\n",addr);
memcpy(&host, eth_hdr->ether_shost, sizeof(host));
addr = (char *) ether_ntoa((struct ether_addr *) eth_hdr->ether_shost);
printf("SOURCE MACC ADDRESS %s\n",addr);
 const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;
const int  ethernet_header_length = 14; 
    int ip_header_length;
    int tcp_header_length;
    int payload_length;
ip_header = packet + ethernet_header_length;
ip_header_length=((*ip_header) & 0x0F);
ip_header_length=ip_header_length*4;
printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
u_char protocol = *(ip_header + 9);
    printf("Protocol number: %d\n", protocol);
if (protocol == 6){

        printf("Protocol is TCP\n");
}
else {
printf("not a tcp\n");
}
tcp_header = packet + ethernet_header_length + ip_header_length;
tcp_header_length=((*(tcp_header+12) & 0x0F) >> 4);
tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = packet_header.caplen -  (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
        }
printf("-------------------------------------------------------------------------------------\n");
}
