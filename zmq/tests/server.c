#include <czmq.h>
#include <zmq.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <pcap.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    //eth_header->ether_dhost[0];

    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
    tcp_header = packet + ethernet_header_length + ip_header_length;
    /* TCP header length is stored in the first half 
       of the 12th byte in the TCP header. Because we only want
       the value of the top half of the byte, we have to shift it
       down to the bottom half otherwise it is using the most 
       significant bits instead of the least significant bits */
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    /* The TCP header length stored in those 4 bits represents
       how many 32-bit words there are in the header, just like
       the IP header length. We multiply by four again to get a
       byte count. */
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

    return;
}
int main (void)
{
    char *device = "enp0s3"; // Указываем конкретный интерфейс
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handler = pcap_create("wlan0", error_buffer);
    pcap_set_rfmon(handler, 1);
    pcap_set_promisc(handler, 1); /* Capture packets that are not yours */
    pcap_set_snaplen(handler,
2048); /* Snapshot length */
    pcap_set_timeout(handler, 1000); /* Timeout in milliseconds */
    pcap_activate(handler);
    /* Snapshot length is how many bytes to capture from each packet. This includes*/
    int snapshot_length = 1024;
    /* End the loop after this many packets are captured */
    int total_packet_count = 200;
    u_char *my_arguments = NULL;

    handler = pcap_open_live(device, snapshot_length, 0, 10000, error_buffer);
    if (handler == NULL) {
    fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
    return 1;  // Завершить программу, если устройство не открылось
}
    pcap_loop(handler, total_packet_count, my_packet_handler, my_arguments);


    // //  Socket to talk to clients
    // void *context = zmq_ctx_new ();
    // void *responder = zmq_socket (context, ZMQ_REP);
    // int rc = zmq_bind (responder, "tcp://*:5555");
    // assert (rc == 0);

    // while (1) {
    //     char buffer [10];
    //     zmq_recv (responder, buffer, 10, 0);
    //     printf ("Received Hello\n");
    //     sleep (1);          //  Do some 'work'
    //     zmq_send (responder, "World", 5, 0);
    // }
    return 0;
}
