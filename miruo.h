#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<stdint.h>
#include<string.h>
#include<limits.h>
#include<math.h>
#include<getopt.h>
#include<signal.h>
#include<errno.h>
#include<fcntl.h>
#include<time.h>
#include<sys/time.h>
#include<sys/resource.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<sys/socket.h>
#include<sys/time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<pcap.h>

/****** COLOR CODE *****/
#define COLOR_RED     1
#define COLOR_GREEN   2
#define COLOR_YELLOW  3
#define COLOR_BLUE    4
#define COLOR_MAGENTA 5
#define COLOR_CYAN    6
#define COLOR_WHITE   7

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
  uint8_t d[14];
  uint16_t type;
} sllhdr;

typedef struct l2hdr{
  union{
    ethhdr eth;
    sllhdr sll;
  } hdr;
} l2hdr;

typedef struct iphdr_row
{
  uint8_t  vih;
  uint8_t  tos;
  uint16_t len;
  uint16_t id;
  uint16_t ffo;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
} iphdr_row;

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
  uint8_t option[40];
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
  uint8_t opt[40];
} tcphdr;

typedef struct tcpsession
{
  uint16_t sid;     //
  uint8_t  sno;     //
  uint8_t  rno;     //
  uint16_t pno;     //
  uint8_t  view;    //
  uint8_t  views;   //
  uint8_t  color;   //
  uint8_t  flags;   //
  uint16_t psize;   //
  uint32_t seqno;   //
  uint32_t ackno;   //
  uint32_t stcnt;   // 現在保持しているパケット数
  uint32_t stall;   // このセッションで飛び交った総パケット数
  uint32_t szall;   // このセッションで飛び交った総データサイズ(L2/L3ヘッダも含む)
  uint8_t  cs[2];   // 現在のステータス(ストックでは使用しない)
  uint8_t  st[2];   // パケットを受け取った時点でのステータス
  uint8_t  optsize; // TCPオプションのサイズ
  uint8_t  opt[40]; // TCPヘッダからコピーしたオプションデータ
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

typedef struct tcpsespool
{
  uint32_t   count;
  tcpsession *free;
} tcpsespool;

typedef struct meminfo
{
  uint64_t   vsz;
  uint64_t   res;
  uint64_t share;
  uint64_t  text;
  uint64_t  data;
  long page_size;
} meminfo;

typedef struct miruopt
{
  pcap_t *p;
  int  loop;               // SININT/SIGTERMが発生したら0になる
  int  alrm;               // タイマ割り込みが発生したら1になる
  int  mode;               // 動作モード。mオプションの値で決定
  int  color;              // カラー表示を有効にするかどうか
  int  lktype;             // データリンク層の種別
  int  pksize;             // キャプチャサイズ
  int  promisc;            // NICをpromiscにするか
  int  rstmode;            // Rオプションの数
  int  verbose;            // vオプションの数
  int  showdata;           //
  int  rsynfind;           // SYNの再送を必ず検出するフラグ
  int  stattime;           // 統計情報を表示する間隔
  int  rt_limit;           // 再送許容間隔(ms)
  int  ct_limit;           // これ以上時間がかかったら表示(ms)
  int  actlimit;           // 最大同時接続数
  char dev[32];            // デバイス名(eth0とかbond0とか)
  char exp[1024];          // フィルタ文字列
  char lkname[256];        // データリンク層の名前?
  char lkdesc[256];        // データリンク層の説明?
  char file[PATH_MAX];     // オフラインモードで読み込むファイル名
  uint32_t err_l2;         //
  uint32_t err_ip;         //
  uint32_t err_tcp;        //
  uint32_t count_ts;       //
  uint32_t count_act;      // 現在の接続数
  uint32_t count_actmax;   // 瞬間最大接続数
  uint64_t count_total;    //
  uint64_t count_view;     //
  uint64_t count_drop;     //
  uint64_t count_timeout;  //
  uint64_t count_rstbreak; //
  uint64_t count_rstclose; //
  tcpsession *tsact;       //
  tcpsespool tspool;       //
  struct tm tm;            //
  struct rusage  now_rs;   //
  struct rusage  old_rs;   //
  struct timeval now_tv;   //
  struct timeval old_tv;   //
  struct itimerval  itv;   //
} miruopt;

extern miruopt opt;

