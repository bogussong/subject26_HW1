#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//IP header
struct ip *iph;

//TCP header
struct tcphdr *tcph;

//filtering function
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    //static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;    
    int chcnt =0;
    int length=pkthdr->len;
    int i;

    //ethernet header    			
    ep = (struct ether_header *)packet;
    
    printf("Dst MAC    : ");
    for(i=0;i<6;i++)
		printf("%02x%c", ep->ether_dhost[i], (i!=5?':':'\n'));
		
	printf("Src MAC    : ");
	for(i=0;i<6;i++)
		printf("%02x%c", ep->ether_shost[i], (i!=5?':':'\n'));	
		
    // add size of ethernet header   
    packet += sizeof(struct ether_header);

    //find protocol type
    ether_type = ntohs(ep->ether_type);

    //IP
    if (ether_type == ETHERTYPE_IP)
    {
        // IP header info
        iph = (struct ip *)packet;
        printf("Dst Address: %s\n", inet_ntoa(iph->ip_dst));
        printf("Src Address: %s\n", inet_ntoa(iph->ip_src));

        //if data, print 
        if (iph->ip_p == IPPROTO_TCP)
        {
			printf("Hi\n");
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("Dst Port   : %d\n" , ntohs(tcph->dest));
            printf("Src Port   : %d\n" , ntohs(tcph->source));
        }

        // packet data
        while(length--)
        {
            printf("%02x", *(packet++)); 
            if ((++chcnt % 16) == 0) 
                printf("\n");
        }
    }
    // if not IP packet
    else
    {
        printf("Not an IP packet\n");
    }
    printf("\n\n");
}    

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct in_addr net_addr, mask_addr;

    //struct bpf_program fp;     
	pcap_t *pcd;  // packet capture descriptor
    

    //get name of device 
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("DEV : %s\n", dev);

    //get network, mask info 
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    if (ret == -1)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET  : %s\n", net);

    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MASK : %s\n", mask);
    printf("----------------------\n\n");

    //get packet capture descriptor   
    pcd = pcap_open_live(dev, BUFSIZ,  1, -1, errbuf); //promiscuous
    
    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }    

    pcap_loop(pcd, atoi(argv[1]), callback, NULL);
    
    return 0;
    
}
