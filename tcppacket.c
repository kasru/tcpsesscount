#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "tcppacket.h"

tcp_packet_t* create_tcp_packet(const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     assert(ip_header);
     assert(tcp_header);

     tcp_packet_t* res = (tcp_packet_t*)malloc(sizeof(tcp_packet_t));
     if (res)
     {
          res->ip.from = ip_header->ip_src.s_addr;
          res->ip.to = ip_header->ip_dst.s_addr;
          res->from_port = ntohs(tcp_header->source);
          res->to_port = ntohs(tcp_header->dest);
          res->seq_num = ntohl(tcp_header->seq);
          res->ack_num = ntohl(tcp_header->ack_seq);
          res->flags = tcp_header->th_flags;
     }
     return res;
}

void destroy_tcp_packet(tcp_packet_t* data)
{
     free(data);
}
