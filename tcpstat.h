#ifndef TCP_SESS_COUNT_TCP_STAT_H
#define TCP_SESS_COUNT_TCP_STAT_H

#include <pcap/pcap.h>

#include "error.h"

typedef struct tcpsesscount_tcpstat tcpsesscount_tcpstat_t;

/// @brief Создать TCP статистику
tcpsesscount_tcpstat_t* tcpsesscount_create_tcpstat();

/// @brief Удалить TCP статистику
void tcpsesscount_destroy_tcpstat( tcpsesscount_tcpstat_t* data );

/// @brief Последний Код ошибки
/// @return Код ошибки
tcpsesscount_error_t tcpsesscount_last_error_code_tcpstat( tcpsesscount_tcpstat_t* data );

/// @brief Последний Текст ошибки
/// @return Текст ошибки или NULL
char* tcpsesscount_last_error_text_tcpstat( tcpsesscount_tcpstat_t* data );

/// @brief Открыть pcap файл
/// @param fname имя файла
/// @return Код ошибки
tcpsesscount_error_t tcpsesscount_open_tcpstat( tcpsesscount_tcpstat_t* data, const char* fname );

/// @brief Собрать статистику
/// @return Код ошибки
tcpsesscount_error_t tcpsesscount_collect_tcpstat( tcpsesscount_tcpstat_t* data );

/// @brief Закрыть pcap файл
/// @param fname имя файла
/// @return Код ошибки
tcpsesscount_error_t tcpsesscount_close_tcpstat( tcpsesscount_tcpstat_t* data );

/// @brief число незавершенных сессий
uint tcpsesscount_count_unfinished_sesssion( tcpsesscount_tcpstat_t* data );

/// @brief число сессий, завершенных штатно (рукопожатием)
uint tcpsesscount_count_finished_sesssion( tcpsesscount_tcpstat_t* data );

/// @brief число сессий, завершенных нештатно
uint tcpsesscount_count_finished_sesssion_abnormaly( tcpsesscount_tcpstat_t* data );


#endif //TCP_SESS_COUNT_TCP_STAT_H
