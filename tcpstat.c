#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "tcppacket.h"
#include "tcpstat.h"
#include "list.h"

struct tcpsesscount_tcpstat
{
     tcpsesscount_error_t last_error_code;
     char pcap_errbuf[PCAP_ERRBUF_SIZE]; ///< текст ошибки
     pcap_t* pcap_descr; ///< дескриптор pcap файла
     list_node_t* tcp_list; ///< список TCP пакетов
     uint count_finished_sesssion; ///< число сессий, завершенных штатно (рукопожатием)
     uint count_finished_sesssion_abnormaly; ///< число сессий, завершенных нештатно
};

tcpsesscount_tcpstat_t* tcpsesscount_create_tcpstat()
{
     tcpsesscount_tcpstat_t *ret = (tcpsesscount_tcpstat_t*)malloc(sizeof(tcpsesscount_tcpstat_t));
     if (ret)
     {
          memset(ret, 0, sizeof(tcpsesscount_tcpstat_t));
     }
     return ret;
}

void tcpsesscount_destroy_tcpstat(tcpsesscount_tcpstat_t *data)
{
     if (data)
     {
          free(data);
     }
}

tcpsesscount_error_t tcpsesscount_last_error_code_tcpstat(tcpsesscount_tcpstat_t *data)
{
     assert(data);
     return data->last_error_code;
}

char* tcpsesscount_last_error_text_tcpstat(tcpsesscount_tcpstat_t *data)
{
     assert(data);
     if (data->pcap_descr)
     {
          return pcap_geterr(data->pcap_descr);
     }
     else
     {
          return data->pcap_errbuf;
     }
}

tcpsesscount_error_t tcpsesscount_open_tcpstat(tcpsesscount_tcpstat_t *data, const char *fname)
{
     assert(data);
     if (fname)
     {
          data->pcap_descr = pcap_open_offline(fname, data->pcap_errbuf);
          if (data->pcap_descr)
          {
               data->last_error_code = tcpsesscount_error_ok;
          }
          else
          {
               data->last_error_code = tcpsesscount_error_pcap_open_offline_failed;
          }
     }
     else
     {
          data->last_error_code = tcpsesscount_error_empty_filename;
     }
     return data->last_error_code;
}

#ifdef TRACE
static char* make_flags_str(uint8_t th_flags)
{
     static char flagbuff[30];
     flagbuff[0] = 0;
     if (th_flags & TH_FIN)
     {
          strcat(flagbuff, "FIN");
     }
     if (th_flags & TH_SYN)
     {
          if (flagbuff[0])
          {
               strcat(flagbuff, ",");
          }
          strcat(flagbuff, "SYN");
     }
     if (th_flags & TH_RST)
     {
          if (flagbuff[0])
          {
               strcat(flagbuff, ",");
          }
          strcat(flagbuff, "RST");
     }
     if (th_flags & TH_PUSH)
     {
          if (flagbuff[0])
          {
               strcat(flagbuff, ",");
          }
          strcat(flagbuff, "PUSH");
     }
     if (th_flags & TH_ACK)
     {
          if (flagbuff[0])
          {
               strcat(flagbuff, ",");
          }
          strcat(flagbuff, "ACK");
     }
     if (th_flags & TH_URG)
     {
          if (flagbuff[0])
          {
               strcat(flagbuff, ",");
          }
          strcat(flagbuff, "URG");
     }
     return flagbuff;
}

static void print_tcp_header(const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     if (tcp_header->th_flags & TH_SYN ||
         tcp_header->th_flags & TH_ACK ||
         tcp_header->th_flags & TH_FIN ||
         tcp_header->th_flags & TH_RST
        )
     {
          char source_ip[INET_ADDRSTRLEN];
          char dest_ip[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
          inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);
          uint16_t source_port = ntohs(tcp_header->source);
          uint16_t dest_port = ntohs(tcp_header->dest);
          char* flags_str = make_flags_str(tcp_header->th_flags);
          printf("%15s:%6d --> %15s:%6d %s\n", source_ip, source_port , dest_ip, dest_port, flags_str);
     }
}
#define PRINT_TCP_HEADER(ip_header, tcp_header) print_tcp_header((ip_header), (tcp_header))
#else
#define PRINT_TCP_HEADER(ip_header, tcp_header)
#endif //TRACE

static tcpsesscount_error_t tcpsesscount_add_packet_to_list(tcpsesscount_tcpstat_t *data, tcp_packet_t* packet)
{
     //Добавляем в конец списка
     data->last_error_code = tcpsesscount_error_ok;
     if (data->tcp_list)
     {
          if (!list_insert_end(data->tcp_list, packet))
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     else
     {
          data->tcp_list = list_create(packet);
          if (!data->tcp_list)
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

/// @brief Сохраняем данные о TCP пакете, который содержит флаг SYN
/// @return код ошибки
static tcpsesscount_error_t tcpsesscount_process_for_syn_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->th_flags == TH_SYN) //инициализация TCP сессии
     {
          // Сохраняем данные о TCP пакете
          tcp_packet_t* packet = create_tcp_packet(ip_header, tcp_header);
          if (packet)
          {
               tcpsesscount_add_packet_to_list(data, packet);
          }
          else
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

/// @brief Компаратор для поиска пакета инициализации сесии (SYN) для пакета data
static int tcpsesscount_cmp_for_syn_packet(void* list_data, const void* data)
{
     tcp_packet_t* list_packet = (tcp_packet_t*)list_data;
     const tcp_packet_t* packet = (const tcp_packet_t*)data;

     if (list_packet->flags == TH_SYN &&
         packet->ip.from == list_packet->ip.to &&
         packet->ip.to == list_packet->ip.from &&
         packet->from_port == list_packet->to_port &&
         packet->to_port == list_packet->from_port &&
         packet->ack_num == (list_packet->seq_num + 1)
        )
     {
          return 1;
     }
     return 0;
}

/// @brief Ищет пакет инициализации сесии для пакета packet, пакет packet содержит флаги SYN+ACK
/// @details Если находим удаляем его из списка пакетов и Добавляем новый пакет в конец списка
/// @return код ошибки
static tcpsesscount_error_t tcpsesscount_process_for_syn_ack_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->syn && tcp_header->ack) //подтверждение инициализации TCP сессии
     {
          tcp_packet_t* packet = create_tcp_packet(ip_header, tcp_header);
          if (packet)
          {
               list_node_t* node = list_find(data->tcp_list, tcpsesscount_cmp_for_syn_packet, packet);
               if (node)
               {
                    list_remove(&data->tcp_list, node);
                    tcpsesscount_add_packet_to_list(data, packet);
               }
               else
               {
                    destroy_tcp_packet(packet);
               }
          }
          else
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

/// @brief Компаратор для поиска двух условий:
/// - подтверждения инифиализации TCP сессии или на подтверждение закрытие TCP сессии (ACK)
/// - запроса на закрытие TCP сессии (FIN)
static int tcpsesscount_cmp_for_ack_any_or_fin_packet(void* list_data, const void* data)
{
     tcp_packet_t* list_packet = (tcp_packet_t*)list_data;
     const tcp_packet_t* packet = (const tcp_packet_t*)data;

     if ((list_packet->flags == TH_ACK) &&
         ( (packet->ip.from == list_packet->ip.to && packet->ip.to == list_packet->ip.from &&
            packet->from_port == list_packet->to_port && packet->to_port == list_packet->from_port) ||
           (packet->ip.from == list_packet->ip.from && packet->ip.to == list_packet->ip.to &&
            packet->from_port == list_packet->from_port && packet->to_port == list_packet->to_port)
         )
        )
     {
          return 1;
     }
     if ((list_packet->flags & TH_FIN) &&
         packet->ip.from == list_packet->ip.to &&
         packet->ip.to == list_packet->ip.from &&
         packet->from_port == list_packet->to_port &&
         packet->to_port == list_packet->from_port &&
         packet->ack_num == (list_packet->seq_num + 1)
        )
     {
          return 1;
     }
     return 0;
}

static tcpsesscount_error_t tcpsesscount_process_for_fin_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->fin) //инициализация закрытия или подтверждение закрытия TCP сессии
     {
          tcp_packet_t* packet = create_tcp_packet(ip_header, tcp_header);
          if (packet)
          {
               list_node_t* node = node = list_find(data->tcp_list, tcpsesscount_cmp_for_ack_any_or_fin_packet, packet);
               if (node)
               {
                    list_remove(&data->tcp_list, node);
                    tcpsesscount_add_packet_to_list(data, packet);
               }
               else
               {
                    destroy_tcp_packet(packet);
               }
          }
          else
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

/// @brief Компаратор для поиска двух условий:
/// - подтверждение инициализации TCP сессии (SYN+ACK)
/// - запроса на закрытие TCP сессии (FIN)
static int tcpsesscount_cmp_for_syn_ack_or_fin_packet(void* list_data, const void* data)
{
     tcp_packet_t* list_packet = (tcp_packet_t*)list_data;
     const tcp_packet_t* packet = (const tcp_packet_t*)data;

     if (( ((list_packet->flags & TH_SYN) && (list_packet->flags & TH_ACK)) || (list_packet->flags & TH_FIN) ) &&
         packet->ip.from == list_packet->ip.to &&
         packet->ip.to == list_packet->ip.from &&
         packet->from_port == list_packet->to_port &&
         packet->to_port == list_packet->from_port &&
         packet->ack_num == (list_packet->seq_num + 1)
        )
     {
          return 1;
     }
     return 0;
}

/// @brief Ищет пакет подтверждение инициализации TCP сессии для пакета packet, пакет packe который содержит флаг ACK
/// @details Если находим удаляем его из списка пакетов. Добавляем новый пакет в конец списка
/// @return код ошибки
static tcpsesscount_error_t tcpsesscount_process_for_ack_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->th_flags == TH_ACK) //ответ на подтверждение инифиализации TCP сессии или на подтверждение закрытие TCP сессии
     {
          tcp_packet_t* packet = create_tcp_packet(ip_header, tcp_header);
          if (packet)
          {
               list_node_t* node = list_find(data->tcp_list, tcpsesscount_cmp_for_syn_ack_or_fin_packet, packet);
               if (node)
               {
                    uint8_t flags = ((tcp_packet_t*)(node->data))->flags;
                    list_remove(&data->tcp_list, node);
                    if (flags & TH_FIN)
                    {
                         ++data->count_finished_sesssion;
                         destroy_tcp_packet(packet);
                    }
                    else
                    {
                         tcpsesscount_add_packet_to_list(data, packet);
                    }
               }
               else
               {
                    destroy_tcp_packet(packet);
               }
          }
          else
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

/// @brief Компаратор для поиска TCP сессии
static int tcpsesscount_cmp_for_tcp_packet(void* list_data, const void* data)
{
     tcp_packet_t* list_packet = (tcp_packet_t*)list_data;
     const tcp_packet_t* packet = (const tcp_packet_t*)data;

     if (
         ( (packet->ip.from == list_packet->ip.to && packet->ip.to == list_packet->ip.from &&
            packet->from_port == list_packet->to_port && packet->to_port == list_packet->from_port) ||
           (packet->ip.from == list_packet->ip.from && packet->ip.to == list_packet->ip.to &&
            packet->from_port == list_packet->from_port && packet->to_port == list_packet->to_port)
         )
        )
     {
          return 1;
     }
     return 0;
}

/// @brief Ищет пакет TCP соединения
/// @details Если находим удаляем его всю информацтю о TCP соединении из списка пакетов.
/// @return код ошибки
static tcpsesscount_error_t tcpsesscount_process_for_rst_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->th_flags & TH_RST) //оборвать соединения
     {
          tcp_packet_t* packet = create_tcp_packet(ip_header, tcp_header);
          if (packet)
          {
               list_node_t* node = node = list_find(data->tcp_list, tcpsesscount_cmp_for_tcp_packet, packet);
               if (node)
               {
                    list_remove(&data->tcp_list, node);
                    ++data->count_finished_sesssion_abnormaly;
               }
               destroy_tcp_packet(packet);
          }
          else
          {
               data->last_error_code = tcpsesscount_error_memory_allocation;
          }
     }
     return data->last_error_code;
}

static tcpsesscount_error_t tcpsesscount_process_packet(tcpsesscount_tcpstat_t *data, const struct ip* ip_header, const struct tcphdr* tcp_header)
{
     (void)data;
     PRINT_TCP_HEADER(ip_header, tcp_header);

     data->last_error_code = tcpsesscount_error_ok;
     if (tcp_header->th_flags == TH_SYN) //инициализация TCP сессии
     {
          tcpsesscount_process_for_syn_packet(data, ip_header, tcp_header);
     }
     else if (tcp_header->syn && tcp_header->ack) //подтверждение инициализации TCP сессии
     {
          tcpsesscount_process_for_syn_ack_packet(data, ip_header, tcp_header);
     }
     else if (tcp_header->fin) //инициализация закрытия или подтверждение закрытия TCP сессии
     {
          tcpsesscount_process_for_fin_packet(data, ip_header, tcp_header);
     }
     if (tcp_header->th_flags == TH_ACK) //ответ на подтверждение инифиализации TCP сессии или на подтверждение закрытие TCP сессии
     {
          tcpsesscount_process_for_ack_packet(data, ip_header, tcp_header);
     }
     if (tcp_header->rst) //оборвать соединения
     {
          tcpsesscount_process_for_rst_packet(data, ip_header, tcp_header);
     }
     return data->last_error_code;
}

static void tcpsesscount_packet_handler(u_char *user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
     assert(user_data);
     (void)pkthdr;

     const struct ether_header* ethernet_header;
     const struct ip* ip_header;
     const struct tcphdr* tcp_header;

     ethernet_header = (const struct ether_header*)packet;
     if (ntohs(ethernet_header->ether_type) == ETHERTYPE_IP)
     {
          ip_header = (const struct ip*)(packet + sizeof(struct ether_header));
          if (ip_header->ip_p == IPPROTO_TCP)
          {
               tcp_header = (const struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
               if (tcpsesscount_process_packet((tcpsesscount_tcpstat_t*)user_data, ip_header, tcp_header) != tcpsesscount_error_ok)
               {
                    pcap_breakloop(((tcpsesscount_tcpstat_t*)user_data)->pcap_descr);
               }
          }
     }
}

tcpsesscount_error_t tcpsesscount_collect_tcpstat(tcpsesscount_tcpstat_t *data)
{
     assert(data);

     int ret = pcap_loop(data->pcap_descr, 0, tcpsesscount_packet_handler, (u_char*)data);
     if (ret < 0)
     {
         if (ret != PCAP_ERROR_BREAK)
         {
              data->last_error_code = tcpsesscount_error_pcap_loop_failed;
         }
     }
     else
     {
          data->last_error_code = tcpsesscount_error_ok;
     }

     return data->last_error_code;
}

tcpsesscount_error_t tcpsesscount_close_tcpstat(tcpsesscount_tcpstat_t *data)
{
     assert(data);

     if (data->pcap_descr)
     {
          pcap_close(data->pcap_descr);
          data->pcap_descr = NULL;
          data->pcap_errbuf[0] = 0;
          data->last_error_code =  tcpsesscount_error_ok;
     }
     else
     {
          data->last_error_code = tcpsesscount_error_pcap_not_open;
     }
     return data->last_error_code;
}

uint tcpsesscount_count_unfinished_sesssion( tcpsesscount_tcpstat_t* data )
{
     assert(data);

     uint count_unfinished_sesssion = 0;
     list_node_t* list = data->tcp_list;
     while (list)
     {
          ///if (((tcp_packet_t*)list->data)->flags == ???)
          ++count_unfinished_sesssion;
          list = list->next;
     }
     return count_unfinished_sesssion;
}

uint tcpsesscount_count_finished_sesssion( tcpsesscount_tcpstat_t* data )
{
     assert(data);
     return data->count_finished_sesssion;
}

uint tcpsesscount_count_finished_sesssion_abnormaly( tcpsesscount_tcpstat_t* data )
{
     assert(data);
     return data->count_finished_sesssion_abnormaly;
}
