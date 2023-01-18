#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/tcp.h>




struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};



struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

struct Apphdr {
    uint32_t unixtime;
    uint16_t length;
    union{
        uint16_t flags;
        uint16_t reserved:3,c_flag:1,s_flag:1,t_flag:1,status:10;
    };
    uint16_t cache;
    uint16_t spacing;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    FILE *file_pointer;
    file_pointer = fopen("213205230_324239714.txt", "a+");
    if(file_pointer == NULL){
        perror("error in opening file");
        exit(1);
    }

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *iph = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ethheader) + iph->iph_ihl*4);
    struct Apphdr *applicationh = (struct Apphdr *)(packet + sizeof(struct ethheader) + iph->iph_ihl*4 + tcph->th_off*4);

    if (tcph->psh != 1){return;}


    const u_char *pointer = (packet + sizeof(struct ethheader) + iph->iph_ihl*4 + tcph->th_off*4 + 12);
    int index  = 0;
    const unsigned int length = (ntohs(applicationh->length));

        fprintf(file_pointer,"----------------PACKET--------------------\n");
        fprintf(file_pointer,"   |-From: %s\n", inet_ntoa(iph->iph_sourceip));
        fprintf(file_pointer,"   |-To: %s\n", inet_ntoa(iph->iph_destip));
        fprintf(file_pointer,"   |-Source Port      : %hu\n",ntohs(tcph->th_sport));
        fprintf(file_pointer,"   |-Destination Port : %hu\n",ntohs(tcph->th_dport));
        fprintf(file_pointer,"   |-Timestamp: %u\n",ntohl(applicationh->unixtime));
        fprintf(file_pointer,"   |-Total_length: %hu\n",ntohs(applicationh->length));
        fprintf(file_pointer,"   |-Data: \n");
        for(index = 0; index  < length; index++ ){
            fprintf(file_pointer,"%02X  ", pointer[index]&0xff);
        }
        applicationh->flags = ntohs((applicationh->flags));
        fprintf(file_pointer,"\n");
        fprintf(file_pointer,"   |-c_flag: %hu\n", ((applicationh->flags>>12) &1));
        fprintf(file_pointer,"   |-s_flag: %hu\n", ((applicationh->flags>>11) &1));
        fprintf(file_pointer,"   |-t_flag: %hu\n", ((applicationh->flags>>10) &1));
        fprintf(file_pointer,"   |-status_code: %hu\n", applicationh->status);
        fprintf(file_pointer,"   |-cache_control: %hu\n", ntohs(applicationh->cache));
    fclose(file_pointer);
}


int main()
{

  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp";
  bpf_u_int32 net = 0;


  // Step 1: Open live pcap session on NIC with name eth3
  handle = pcap_open_live("lo", BUFSIZ, 1, 1000, errbuf); 
  if(handle == NULL){
    perror("error here");
    exit(1);
  }

  // Step 2: Compile filter_exp into BPF psuedo-code
        
  if(pcap_compile(handle, &fp, filter_exp, 0, net)){
    //pcap_geterr(handle);
   printf("error\n");
  }
  if(!pcap_setfilter(handle, &fp)){
    printf("setfilter succeded");
  }                             

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                

  pcap_close(handle);   //Close the handle 
  return 0;
}