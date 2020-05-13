#ifndef TCP_SESS_COUNT_ERROR_H
#define TCP_SESS_COUNT_ERROR_H


/// @brief Коды ошибок
enum tcpsesscount_error
{
     tcpsesscount_error_ok = 0,
     tcpsesscount_error_memory_allocation,
     tcpsesscount_error_usage,
     tcpsesscount_error_create_tcpstat,
     tcpsesscount_error_empty_filename,
     tcpsesscount_error_pcap_open_offline_failed,
     tcpsesscount_error_pcap_not_open,
     tcpsesscount_error_pcap_loop_failed,
};

typedef enum tcpsesscount_error tcpsesscount_error_t;


#endif //TCP_SESS_COUNT_ERROR_H
