#ifndef TCP_SESS_COUNT_TCP_PACKET_H
#define TCP_SESS_COUNT_TCP_PACKET_H

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct tcp_packet
{
     struct ip_packet
     {
          uint32_t from;
          uint32_t to;
     } ip;

     uint16_t from_port;
     uint16_t to_port;
     uint32_t seq_num;
     uint32_t ack_num;
     uint8_t flags;
};

typedef struct tcp_packet tcp_packet_t;

tcp_packet_t* create_tcp_packet(const struct ip* ip_header, const struct tcphdr* tcp_header);
void destroy_tcp_packet(tcp_packet_t* data);

#endif //TCP_SESS_COUNT_TCP_PACKET_H
