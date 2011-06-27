#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<math.h>
#include<getopt.h>
#include<signal.h>
#include<errno.h>
#include<time.h>
#include<sys/time.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>

/****** COLOR CODE *****/
#define COLOR_RED    1
#define COLOR_GREEN  2
#define COLOR_YELLOW 3
#define COLOR_BLUE   4
#define COLOR_WHITE  7

/***** MIRUO MODE *****/
#define MIRUO_MODE_TCP_SESSION 1
#define MIRUO_MODE_HTTP        2
#define MIRUO_MODE_MYSQL       3

/***** TCP STATUS *****/
#define MIRUO_STATE_TCP_LISTEN     1
#define MIRUO_STATE_TCP_SYN_SENT   2
#define MIRUO_STATE_TCP_SYN_RECV   3
#define MIRUO_STATE_TCP_EST        4
#define MIRUO_STATE_TCP_FIN_WAIT1  5
#define MIRUO_STATE_TCP_FIN_WAIT2  6
#define MIRUO_STATE_TCP_CLOSE_WAIT 7
#define MIRUO_STATE_TCP_LAST_ACK   8
#define MIRUO_STATE_TCP_CLOSED     9
#define MIRUO_STATE_TCP_TIME_WAIT  10

typedef struct L7data{
  uint64_t session;
  uint32_t tcpstate;
  uint8_t data[65536];
  struct L7data *prev;
  struct L7data *next;
} L7data;

typedef struct TCPdata{
  uint32_t saddr;
  uint32_t daddr;
  uint16_t sport;
  uint16_t dport;
  uint8_t data[65536];
  struct TCPdata *prev;
  struct TCPdata *next;
} TCPdata;

typedef struct IPdata{
  uint16_t id;
  uint32_t saddr;
  uint32_t daddr;
  uint8_t data[65536];
  struct IPdata *prev;
  struct IPdata *next;
} IPdata;

typedef struct ethhdr{
  uint8_t  smac[6];
  uint8_t  dmac[6];
  uint16_t type;
} ethhdr;

typedef struct sllhdr{
  uint16_t type;
} sllhdr;

typedef struct l2hdr{
  union{
    ethhdr eth;
    sllhdr sll;
  } hdr;
} l2hdr;

typedef struct iphdr
{
  uint8_t  Ver;
  uint8_t  IHL;
  uint8_t  TOS;
  uint16_t len;
  uint16_t id;
  uint8_t  flags;
  uint16_t offset;
  uint8_t  TTL;
  uint8_t  Protocol;
  uint16_t Checksum;
  struct in_addr src;
  struct in_addr dst;
  uint32_t options[10];
} iphdr;

typedef struct ipdata
{
  struct timeval ts;
  iphdr  h;
  u_char d[65536];
} ipdata;

typedef struct tcphdr
{
  uint16_t sport;
  uint16_t dport;
  uint32_t seqno;
  uint32_t ackno;
  uint8_t  offset;
  uint8_t  flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent;
  uint32_t opt[11];
} tcphdr;

typedef struct tcpsession
{
  uint16_t sid;
  uint8_t  sno;
  uint8_t  rno;
  uint8_t  view;
  uint8_t  views;
  uint8_t  color;
  uint8_t  flags;
  uint32_t seqno;
  uint32_t ackno;
  uint8_t  cs[2]; // 現在のステータス(ストックでは使用しない)
  uint8_t  st[2]; // パケットを受け取った時点でのステータス
  union {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_storage storage;
  } src;
  union {
    struct sockaddr addr;
    struct sockaddr_in in;
    struct sockaddr_storage storage;
  } dst;
  struct timeval ts;
  struct tcpsession *stok;
  struct tcpsession *last;
  struct tcpsession *prev;
  struct tcpsession *next;
} tcpsession;

typedef struct tcpdata
{
  struct timeval ts;
  iphdr  ih;
  tcphdr th;
  u_char data[65536];
} tcpdata;

typedef struct tcpsession_pool
{
  uint32_t   count;
  tcpsession *free;
} tcpsession_pool;

typedef struct miruopt
{
  pcap_t *p;
  int  mode;
  int  loop;
  int  color;
  int  lktype;
  int  pksize;
  int  promisc;
  int  verbose;
  int  setalrm;
  int  maxcount;
  int  ac_count;
  int  ts_count;
  int  rstclose;
  int  stattime;
  int  interval;
  int  rt_limit;
  char dev[32];
  char exp[1024];
  char lkname[256];
  char lkdesc[256];
  char file[PATH_MAX];
  uint32_t L2err;
  uint32_t IPerr;
  uint32_t TCPerr;
  uint64_t total_count;
  uint64_t view_count;
  uint64_t timeout_count;
  uint64_t rstbreak_count;
  struct timeval tv;
  struct tm     *tm;
} miruopt;

extern miruopt opt;


