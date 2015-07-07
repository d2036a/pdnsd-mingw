#include <stdint.h>

typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;

#ifndef random
#define random rand
#endif
#ifndef srandom
#define srandom srand
#endif
#ifndef inet_aton
#define inet_aton(N,A) ( (A)->s_addr = inet_addr(N), ( (A)->s_addr != INADDR_NONE ) )
#endif

#ifndef IP_RECVDSTADDR
#define IP_RECVDSTADDR IP_PKTINFO
#endif

#ifndef SOL_IPV6
#define SOL_IPV6 AF_INET6
#endif

struct sockaddr_un{ 
         short   sun_family;           /*AF_UNIX*/ 
         char    sun_path[108];        /*path name */ 
};

/* ------------------------------------------------- */
/*                   Posix.FileSys                   */
/* ------------------------------------------------- */

#define S_IRGRP 0000040
#define S_IROTH 0000004
#define S_IRWXG 0000070
#define S_IRWXO 0000007
#define S_ISGID 0002000
#define S_ISUID 0004000
#define S_IWGRP 0000020
#define S_IWOTH 0000002
#define S_IXGRP 0000010
#define S_IXOTH 0000001

// Do not exist in a windows filesystem
#define S_IFLNK 0
#define S_IFSOCK 0
#define S_ISVTX 0

#define O_NOCTTY 0x8000
#define O_NONBLOCK 0x4000

// Synchronized writes? Safety of any kind? ... and windows?! hell no!
#define O_SYNC 0

/* ------------------------------------------------- */
/*                      Syslog                       */
/* ------------------------------------------------- */

#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

#define LOG_PRIMASK     0x07    /* mask to extract priority part (internal) */

#define LOG_PID    0x01 /* include PID in output */
#define LOG_CONS   0x02 /* dump to console (meaningless for windows?) */
#define LOG_ODELAY 0x04 /* delay open; meaningless---always open */
#define LOG_NDELAY 0x08 /* don't delay; meaningless */
#define LOG_NOWAIT 0x10 /* ignored and obsolete anyways */
#define LOG_PERROR 0x20 /* print to standard error, honoured */

#define LOG_AUTH 1
#define LOG_CRON 2
#define LOG_DAEMON 3
#define LOG_KERN 4
#define LOG_LOCAL0 5
#define LOG_LOCAL1 6
#define LOG_LOCAL2 7
#define LOG_LOCAL3 8
#define LOG_LOCAL4 9
#define LOG_LOCAL5 10
#define LOG_LOCAL6 11
#define LOG_LOCAL7 12
#define LOG_LPR 13
#define LOG_MAIL 14
#define LOG_NEWS 15
#define LOG_SYSLOG 16
#define LOG_USER 17
#define LOG_UUCP 18

/* IPV6 */
# define IN6_ARE_ADDR_EQUAL(a,b) \
        ((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0])         \
         && (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1])      \
         && (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2])      \
         && (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))

