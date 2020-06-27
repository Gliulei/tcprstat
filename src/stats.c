/**
 *   tcprstat -- Extract stats about TCP response times
 *   Copyright (C) 2010  Ignacio Nin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/

/**
 * Of course this implementation has to change :)
 * Initial implementation: a simple linked list
 */

#define TIMEOUT_USEC           10000000
#define CLEAN_INTERVAL_USEC    2000000
#define INITIAL_STAT_SZ         2000

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pthread.h>
#include <tcprstat.h>
#include <stdio.h>

#include "stats-hash.h"
#include <ctype.h>

struct hash *sessions;

unsigned long *stats; //�����������¼�˳�ϵͳ�ͽ�ϵͳ��ʱ���
unsigned statscount,  //����ʱ���ʱ����ܰ���
statssz;

pthread_mutex_t sessions_mutex = PTHREAD_MUTEX_INITIALIZER,
    stats_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t clean_thread_id;

int exiting;

static void *clean_thread(void *);
static int lock_sessions(void), unlock_sessions(void),
    lock_stats(void), unlock_stats(void);

static unsigned long isqrt(unsigned long) __attribute__ ((const));
    
int
init_stats(void) {
    stats = malloc((statssz = INITIAL_STAT_SZ) * sizeof(unsigned long));
    if (!stats)
        abort();
    
    sessions = hash_new();
    if (!sessions)
        abort();
    
    // Stat cleaner thread
    pthread_create(&clean_thread_id, NULL, clean_thread, NULL);
    
    return 0;
    
}

int
free_stats(void) {
    exiting = 1;
    pthread_kill(clean_thread_id, SIGINT);
    pthread_join(clean_thread_id, NULL);
    
    lock_sessions();

    hash_del(sessions);
    
    unlock_sessions();
    
    lock_stats();
    
    free(stats);
    
    unlock_stats();
    
    return 0;
    
}

void gen_cmd(char *src, const char *separator, char *dest) {
    char *pNext;
    //int count = 0;
    if (src == NULL || strlen(src) == 0)
    {
        return;
    }

    if (separator == NULL || strlen(separator) == 0)
    {
        return; 
    }

    pNext = strtok(src, separator);
    while(pNext != NULL) 
    {
        if(NULL == strstr(pNext, "*") && NULL == strstr(pNext, "$"))
        {
            //*dest++ = pNext;
           // ++count;
           strcat(dest, pNext);
           strcat(dest, " ");
        }
        pNext = strtok(NULL, separator);  
        
    }  
} 


void gen_val(char *src, char *dest) {
    int buf_len = 0;
    switch(src[0]) {
        case '$':
            buf_len = atoi(src + 1);
            strncpy(dest, src+5, buf_len);
        case '*':
            /* For null multi-bulk replies (like timeouts from brpoplpush): */
            if(memcmp(src + 1, "-1", 2) == 0) {
                dest = src;
            }
            /* fall through */

        default:
            dest = src;
    }  
} 

int time2Str(time_t timep, char* str, size_t len)
{
    struct tm *tmp_time = localtime(&timep);
    strftime(str, len, "%Y-%m-%d %H:%M:%S", tmp_time);
    return 0;
}

char* trim_left(char *str) {
  int len = strlen(str);
  char *cur = str;

  while (*cur && isspace(*cur))
  {
    ++cur;
    --len;
  }

  if (str != cur) memmove(str, cur, len + 1);

  return str;
}

void trim_right(char *str) {
  int len = strlen(str);
  
  char *cur = str + len - 1;

  while (cur != str && isspace(*cur)) --cur;
  cur[isspace(*cur) ? 0 : 1] = '\0';
  
  //return str;
}

char* trim(char *str) {
  trim_right(str);
  trim_left(str);
  return str;
}

int
inbound(struct timeval tv, char* data, struct in_addr laddr, struct in_addr raddr,
        uint16_t lport, uint16_t rport)
{
    lock_sessions();
    char buf[50496]={'\0'};
    gen_cmd(data, "\r\n", buf);
    trim_right(buf);
    
    hash_set(sessions, laddr.s_addr, raddr.s_addr, lport, rport, tv, buf);
    unlock_sessions();
    return 0;
}

//ʱ��ͳ�ƹؼ���������get_flush_stats  outbound

int
outbound(struct timeval tv, char* data, struct in_addr laddr, struct in_addr raddr,char* l_ip, char* r_ip,
         uint16_t lport, uint16_t rport)
{
    struct timeval start;
    unsigned long newstat;
    //char* res = NULL;
    // int n = 0;
    char* key = NULL;
    
    lock_sessions();
    
    if (hash_get_rem(sessions, laddr.s_addr, raddr.s_addr, lport, rport, &start, &key))
    {
        newstat = (tv.tv_sec - start.tv_sec) * 1000000 +
                    (tv.tv_usec - start.tv_usec); //����ǳ�ϵͳ��ʱ��-��ϵͳ��ʱ�����Ҳ���ǽ��뱾ϵͳ�ͳ���ϵͳ��ʱ���
                    
        unlock_sessions();

        // Add a stat
        lock_stats();
        
        if (statscount == statssz) {
            stats = realloc(stats, (statssz *= 2) * sizeof(unsigned long));
            if (!stats)
                abort();
            
        }
        if(strlen(data) > 0) {
            char res[1024] = {'\0'};
            gen_val(data, res);
            trim_right(res);
            //printf("res:%s", res);
            zlog_info(g_zlog_conn, "cmd=%s, res=%s, from=%s:%d, to=%s:%d, start_timestamp:%ld.%ld, end_timestamp:%ld.%ld, delay_time:%ld", key, res, l_ip, lport, r_ip, rport, start.tv_sec, start.tv_usec, tv.tv_sec, tv.tv_usec, newstat);
            // n = snprintf(buf, sizeof(buf), "timestamp:%ld.%ld     cmd:%s    res:%s\r\n", start.tv_sec, start.tv_usec, key, data);
            // if(n > 0){
                // write(g_log_fd, buf, (size_t)n);
            // }
        }
        /*if(newstat > g_delay_time && g_log_fd > 0) {
            n = snprintf(buf, sizeof(buf), "timestamp:%ld.%ld     delay_time:%ld\r\n", start.tv_sec, start.tv_usec, newstat);
            if(n > 0)
                write(g_log_fd, buf, (size_t)n);
        }*/
        stats[statscount ++] = newstat; //
        unlock_stats();
        
        return 0;
        
    }

    test2();
            
    unlock_sessions();
    
    return 1;    
    
}

static int
lock_stats(void) {
    return pthread_mutex_lock(&stats_mutex);
    
}

static int
unlock_stats(void) {
    return pthread_mutex_unlock(&stats_mutex);
    
}

static int
lock_sessions(void) {
    return pthread_mutex_lock(&sessions_mutex);
    
}

static int
unlock_sessions(void) {
    return pthread_mutex_unlock(&sessions_mutex);
    
}

static void *
clean_thread(void *arg) {
    struct timeval tv;
    struct timespec ts = {
        CLEAN_INTERVAL_USEC / 1000000,
        (CLEAN_INTERVAL_USEC % 1000000) * 1000
    };
    
    do {
        
        nanosleep(&ts, NULL);
    
        lock_sessions();
        
        gettimeofday(&tv, NULL);
        
        // Notice we only advance when we don't delete
        hash_clean(sessions, tv.tv_sec * 1000000 + tv.tv_usec - TIMEOUT_USEC);
            
        unlock_sessions();
        
    }
    while (!exiting);
    
    return NULL;
    
}

/*** Results ***/
struct stats_results { //һ��ʱ���ڵ�ͳ����Ϣ���뵽�ýṹ����get_flush_stats  outbound
    unsigned long *stats;
    unsigned statscount, statssz;
    
    int sorted;
    
};

static void sort_results(struct stats_results *results);
int compare_stats(const void *, const void *);

struct stats_results *
get_flush_stats(void) {  //ʱ��ͳ�ƹؼ���������get_flush_stats  outbound
    struct stats_results *ret;
    
    ret = malloc(sizeof(struct stats_results));
    if (!ret)
        abort();
    memset(ret, 0, sizeof(struct stats_results));
    
    lock_stats();
    
    ret->stats = stats;
    ret->statscount = statscount; //��ret->statscountָ��ͳ�ƺõĸ�����Ϣ  ���ʱ������Ѿ�ͳ�ƺõ�ʱ�ӷ����˸�������ڸú���wait����ͳ��
    ret->statssz = statssz;
    
    ret->sorted = 0;
    
    stats = malloc((statssz = INITIAL_STAT_SZ) * sizeof(unsigned long)); //�����µ���������ͳ����һ��ʱ�����ڵ�ʱ���ֵ
    if (!stats)
        abort();
    statscount = 0;
    
    unlock_stats();
    
    return ret;
    
}

static void
sort_results(struct stats_results *results) {
    qsort(results->stats, results->statscount, sizeof(unsigned long),
          compare_stats);
    results->sorted = 1;
    
}

int
compare_stats(const void *void1, const void *void2) {
    const unsigned long *stat1, *stat2;
    stat1 = void1;
    stat2 = void2;
    
    if (*stat1 < *stat2)
        return -1;
    else if (*stat1 > *stat2)
        return 1;
    else
        return 0;
    
}

int
free_results(struct stats_results *results) {
    free(results->stats);
    free(results);
    
    return 0;
    
}

unsigned
stats_count(struct stats_results *results, int percentile) {
    if (percentile == 0 || percentile == 100)
        return results->statscount;
    
    return (results->statscount * percentile) / 100;
    
}

unsigned long
stats_avg(struct stats_results *results, int percentile) {
    unsigned long n;
    unsigned long avg = 0;
    unsigned long i;
    
    if (!results->statscount)
        return 0;

    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else {
        if (!results->sorted)
            sort_results(results);
        
        n = (results->statscount * percentile ) / 100;
        
    }
    
    if (!n)
        return 0;
    
    for (i = 0; i < n; i ++)
        avg += results->stats[i];
    
    avg /= n;
    
    return avg;
    
}

unsigned long
stats_sum(struct stats_results *results, int percentile) {
    unsigned long n;
    unsigned long sum = 0;
    unsigned long i;
    
    if (!results->statscount)
        return 0;

    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else {
        if (!results->sorted)
            sort_results(results);
        
        n = (results->statscount * percentile ) / 100;
        
    }
    
    if (!n)
        return 0;
    
    for (i = 0; i < n; i ++)
        sum += results->stats[i];
    
    return sum;
    
}

unsigned long
stats_sqs(struct stats_results *results, int percentile) {
    unsigned long n;
    unsigned long sqs = 0;
    unsigned long i;
    
    if (!results->statscount)
        return 0;

    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else {
        if (!results->sorted)
            sort_results(results);
        
        n = (results->statscount * percentile ) / 100;
        
    }
    
    if (!n)
        return 0;
    
    for (i = 0; i < n; i ++)
        sqs += results->stats[i] * results->stats[i];
    
    return sqs;
    
}

extern int g_delay_time;
unsigned long
stats_delay_count(struct stats_results *results, int percentile) {
    unsigned long n;
    unsigned long i;
    unsigned long count = 0;
    
    if (!results->statscount)
        return 0;

    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else {
        if (!results->sorted)
            sort_results(results);
        
        n = (results->statscount * percentile ) / 100;
        
    }
    
    if (!n)
        return 0;
    
    
    for (i = 0; i < n; i ++) {
        if(results->stats[i] >= g_delay_time)
            count++;
    }

    return count;
    
}


unsigned long
stats_min(struct stats_results *results, int percentile) {
    if (!results->statscount)
        return 0;
    
    if (!results->sorted)
        sort_results(results);
    
    return results->stats[0];
    
}

unsigned long
stats_max(struct stats_results *results, int percentile) {
    unsigned long n;
    
    if (!results->statscount)
        return 0;
    
    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else
        n = (results->statscount * percentile) / 100;
    
    if (!n)
        return 0;   // Is this correct? or should [0] be returned?
    
    if (!results->sorted)
        sort_results(results);
    
    return results->stats[n - 1];
    
}

unsigned long
stats_med(struct stats_results *results, int percentile) {
    unsigned long n;
    
    if (!results->statscount)
        return 0;
    
    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else
        n = (results->statscount * percentile) / 100;
    
    if (!n)
        return 0;   // Is this correct? or should [0] be returned?
    
    if (!results->sorted)
        sort_results(results);
    
    return results->stats[n / 2];
    
}

unsigned long
stats_var(struct stats_results *results, int percentile) {
    unsigned long avg, var;
    unsigned long n;
    unsigned long i;
    
    if (!results->statscount)
        return 0;
    
    if (percentile == 0 || percentile == 100)
        n = results->statscount;
    else
        n = (results->statscount * percentile) / 100;
    
    if (!n)
        return 0;   // Is this correct? or should [0] be returned?
    
    avg = stats_avg(results, percentile);
    
    // Variance is the sum of squares, divided by n, less the square of the avg
    
    // Sum of squares
    var = 0;
    for (i = 0; i < n; i ++)
        var += results->stats[i] * results->stats[i];
    
    var /= n;
    var -= avg * avg;
    
    return var;
    
}

unsigned long
stats_std(struct stats_results *results, int percentile) {
    return isqrt(stats_var(results, percentile));
    
}

// Based in code from
// http://www.codecodex.com/wiki/Calculate_an_integer_square_root#C
// It stipulates that content is available under the
// GNU Free Documentation License
static unsigned long
isqrt(unsigned long x)
{
    unsigned long op, res, one;

    op = x;
    res = 0;

    // "one" starts at the highest power of four <= than the argument.
    one = 1;
    while (one < op) one <<= 2;
    while (one > op) one >>= 2;

    while (one) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;
        }
        res >>= 1;
        one >>= 2;
    }
    
    return res;
    
}
