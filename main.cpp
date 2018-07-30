#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(u_char* mac){
        for(int i=0;i<6;i++){
                if(i==5)
                        printf("%02X",mac[i]);
                else
                        printf("%02X:",mac[i]);
	}
}


void print_eth(ether_header* eth_h){
	printf("\n[+]eth_type:[0x%04x]-",ntohs(eth_h->ether_type));
        printf("\n[+]dst_mac ~ ");
        print_mac(eth_h->ether_dhost);
        printf("\n[+]src_mac ~ ");
        print_mac(eth_h->ether_shost);

}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  char dst_m[6];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
   
  while (true) {
    int length=0;
    struct pcap_pkthdr* header;
    const u_char* packet;
    ether_header* eth_h;
    int res = pcap_next_ex(handle, &header, &packet);
    length = header->caplen; 
    eth_h = (ether_header*)packet;
    ip* ip_h =(ip*)(packet + sizeof(ether_header));
    tcphdr* tcp_h = (tcphdr*)((u_char*)ip_h + ip_h->ip_hl*4);
    
    packet +=sizeof(ether_header)+sizeof(ip)+sizeof(tcphdr);
    printf("++++++++++++++++++++++%d++++++++++++++++++++++++",sizeof(packet));
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    
    print_eth(eth_h);

    if(ntohs(eth_h->ether_type) == ETHERTYPE_IP){
	printf("\n src ip: %s\n",inet_ntoa(ip_h->ip_src));
	printf("\n dst ip: %s\n",inet_ntoa(ip_h->ip_dst));
    }
    if(ip_h->ip_p == IPPROTO_TCP){
	printf("\n src port: %d\n",ntohs(tcp_h->th_sport));
	printf("\n dst port: %d\n",ntohs(tcp_h->th_dport));
	printf("==========================================");
    }
    //int heder_len = 
    //length = length-(int)();
    printf("=====================%d=====================",length);
    while(length--){
	printf("%02X",*(packet++));
    }
 }

  pcap_close(handle);
  return 0;
}
