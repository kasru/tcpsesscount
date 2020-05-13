/*
Практическое задание
Напишите утилиту tcpsesscount на C, которая умеет в переданном pcap файле с сетевым
дампом найти все замеченные TCP-сессии и вывести по ним статистику:
• число незавершенных сессий;
• число сессий, завершенных штатно (рукопожатием);
• число сессий, завершенных нештатно.
2Вызываться утилита будет как-то так:
Листинг 1
sudo tcpdump -w ~/dump.cap
... waiting several minutes ...
^C
tcpsesscount ~/dump.cap
Спасибо!
*/

#include <stdio.h>

#include "tcpstat.h"

static void usage(char* name)
{
     printf("usage: %s <file>\n", name);
}

static void failed(char* name, tcpsesscount_error_t code)
{
     fprintf(stderr, "%s failed. Error code %d\n", name, (int)code);
}

static void failed_text(char* name, char* text)
{
     fprintf(stderr, "%s %s\n", name, text);
}

static void print_tcpstat( tcpsesscount_tcpstat_t* data )
{
     printf("Count unfinished TCP sesssion: %u\n", tcpsesscount_count_unfinished_sesssion(data));
     printf("Count finished TCP sesssion: %u\n", tcpsesscount_count_finished_sesssion(data));
     printf("Count finished TCP sesssion abnormaly: %u\n", tcpsesscount_count_finished_sesssion_abnormaly(data));
}

int main(int argc, char **argv)
{
     if(argc < 2)
     {
          usage(argv[0]);
          return tcpsesscount_error_usage;
     }

     tcpsesscount_error_t ret = tcpsesscount_error_ok;
     tcpsesscount_tcpstat_t* tcpstat = tcpsesscount_create_tcpstat();
     if(tcpstat)
     {
          ret = tcpsesscount_open_tcpstat(tcpstat, argv[1]);
          if(ret == tcpsesscount_error_ok)
          {
               ret = tcpsesscount_collect_tcpstat(tcpstat);
          }
          if(ret == tcpsesscount_error_ok)
          {
               print_tcpstat(tcpstat);
          }
          else
          {
               failed_text("Error:", tcpsesscount_last_error_text_tcpstat(tcpstat));
          }
          tcpsesscount_close_tcpstat(tcpstat);
          tcpsesscount_destroy_tcpstat(tcpstat);
          tcpstat = NULL;
     }
     else
     {
          failed_text("Error:", "Can't create tcpstat");
          ret = tcpsesscount_error_create_tcpstat;
     }

     if(ret != tcpsesscount_error_ok)
     {
          failed(argv[0], ret);
     }
     return (int)ret;
}
