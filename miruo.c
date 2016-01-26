#include "miruo.h"

miruopt opt;
miruopt_dpi dpi;
void version()
{
  const char *libpcap = pcap_lib_version();
  printf("%7s version %s\n",PACKAGE_NAME, PACKAGE_VERSION);
  if(libpcap){
    printf("%s\n", libpcap);
  }
}

void usage()
{
  version();
  printf("usage: miruo [option] [expression]\n");
  printf("  option\n");
  printf("   -h, --help                     # help\n");
  printf("   -V, --version                  # version\n");
  printf("   -i, --interface=dev            # eth0,bond0,any...\n");
  printf("   -v, --view-data=NUM            # \n");
  printf("   -T, --long-connect=time[ms]    # Threshold of connection time for lookup. Default 0ms(off)\n");
  printf("   -t, --long-delay=time[ms]      # Threshold of long delay time for lookup. Default 0ms(off)\n");
  printf("   -r, --retransmit=time[ms]      # Threshold of retransmit time for lookup. Default 1000ms\n");
  printf("   -s, --stat=interval[sec]       # statistics view interval. Default 0sec(off)\n");
  printf("   -f, --file=file                # read file(for tcpdump -w)\n");
  printf("   -S, --syn=[0|1]                # syn retransmit lookup mode.default=1. 0=ignore 1=lookup\n");
  printf("   -R, --rst=[0|1|2]              # rst lookup mode.default=1. (see README)\n");
  printf("   -F, --fragment=[0|1]           # ip fragment lookup. default=1\n");
  printf("   -C, --color=[0|1]              # color 0=off 1=on\n");
  printf("   -L, --session-limit=NUM        # active session limit. Default 1024\n");
  printf("   -l, --segment-limit=NUM        # active segment limit. Default 65536\n");
  printf("   -m, --dpi-mode=mode            # deep packet inspection mode. (now support only http)\n");
  printf("   -q, --quiet                    # \n");
  printf("       --all                      # all session lookup\n");
  printf("       --live                     # live mode(all segment lookup)\n");
  printf("\n");
  printf("  expression: see man tcpdump\n");
  printf("\n");
  printf("  ex)\n");
  printf("    miruo -i eth0 -s 10 2>statistics.log\n");
  printf("    miruo -i eth0 host 192.168.0.100 and port 80\n");
  printf("    miruo -i eth0 -T5000 src host 192.168.0.1\n");
}

int is_numeric(char *str)
{
  if(str == NULL){
    return(0);
  }
  if(*str == 0){
    return(0);
  }
  if((*str == '-') || (*str == '+')){
    str++;
  }
  while(*str){
    if((*str < '0') || (*str > '9')){
      return(0);
    }
    str++;
  }
  return(1);
}

int get_cpu_utilization()
{
  int cpu;
  uint64_t rus;
  uint64_t cus;
  struct timeval  rtv;
  struct timeval  ctv;
  struct timeval nctv;
  struct timeval octv;
  static struct rusage  nrusa;
  static struct rusage  orusa;
  static struct timeval ntime = {0,0};
  static struct timeval otime = {0,0};
  if(otime.tv_sec == 0){
    getrusage(RUSAGE_SELF, &(orusa));
    gettimeofday(&(otime), NULL);
    return(0);
  }
  getrusage(RUSAGE_SELF, &(nrusa));
  gettimeofday(&(ntime), NULL);
  timeradd(&(nrusa.ru_stime), &(nrusa.ru_utime), &nctv);
  timeradd(&(orusa.ru_stime), &(orusa.ru_utime), &octv);
  timersub(&(ntime), &(otime), &rtv);
  timersub(&(nctv), &(octv), &ctv);
  cus  = ctv.tv_sec;
  cus *= 1000000;
  cus += ctv.tv_usec;
  rus  = rtv.tv_sec;
  rus *= 1000000;
  rus += rtv.tv_usec;
  cpu = rus ? cus * 1000 / rus : 0;
  cpu = (cpu > 1000) ? 1000 : cpu;
  memcpy(&(otime), &(ntime), sizeof(struct timeval));
  memcpy(&(orusa), &(nrusa), sizeof(struct rusage));
  return(cpu);
}

meminfo *get_memmory()
{
  int   i;
  int   f;
  char *r;
  char  buff[256], cmd[256];
  static meminfo mi;
  FILE *fp;

  memset(buff, 0, sizeof(buff));
  mi.page_size = sysconf(_SC_PAGESIZE);
  f = open("/proc/self/statm", O_RDONLY);
  if(f == -1){
    memset(&mi, 0, sizeof(meminfo));
    snprintf(cmd, sizeof(cmd), "/bin/ps -o pid=,vsz=,rss= -p %d", getpid());
    fp = popen(cmd, "r");
    if(fp == NULL){
      return(NULL);
    }
    fread(buff, 1, sizeof(buff) -1, fp);
    pclose(fp);
    i = 1;
    r = strtok(buff, " ");
    if(!r || atoi(r) != getpid()){
      return(NULL);
    }
    while(r=strtok(NULL, " ")){
      switch(++i){
        case 2:
          mi.vsz = (uint64_t)atoi(r) * 1024;
          break;
        case 3:
          mi.res = (uint64_t)atoi(r) * 1024;
          break;
      }
    }
    return(&mi);
  }
  read(f, buff, sizeof(buff) - 1);
  close(f);
  i = 1;
  r = strtok(buff, " ");
  mi.vsz = atoi(r) * mi.page_size;
  while(r=strtok(NULL, " ")){
    switch(++i){
      case 2:
        mi.res = atoi(r) * mi.page_size;
        break;
      case 3:
        mi.share = atoi(r) * mi.page_size;
        break;
      case 4:
        mi.text = atoi(r) * mi.page_size;
        break;
      case 6:
        mi.data = atoi(r) * mi.page_size;
        break;
    }
  }
  return(&mi);
}

void get_kmg_string(uint8_t *str, uint64_t val)
{
  if(val > 1024 * 1024 * 1024){
    sprintf(str, "%lluGB", val / 1024 / 1024 / 1024);
  }else if(val > 1024 * 1024){
    sprintf(str, "%lluMB", val / 1024 / 1024);
  }else if(val > 1024){
    sprintf(str, "%lluKB", val / 1024);
  }else{
    sprintf(str, "%lluB", val);
  }
}

uint16_t get_l3type(l2hdr *hdr)
{
  switch(opt.lktype){
    case DLT_EN10MB:
      return(hdr->hdr.eth.type);
    case DLT_LINUX_SLL:
      return(hdr->hdr.sll.type);
  }
  return(0);
}

char *tcp_state_str(int state)
{
  static char *state_string[]={
    "-",
    "LISTEN",
    "SYN_SENT",
    "SYN_RECV",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "LAST_ACK",
    "CLOSED",
    "TIME_WAIT",
  };
  return(state_string[state]);
}

char *tcp_flag_str(uint8_t flags)
{
  static char fstr[16];
  strcpy(fstr, "------");
  if(flags & 1){
    fstr[5]='F';
  }
  if(flags & 2){
    fstr[4]='S';
  }
  if(flags & 4){
    fstr[3]='R';
  }
  if(flags & 8){
    fstr[2]='P';
  }
  if(flags & 16){
    fstr[1]='A';
  }
  if(flags & 32){
    fstr[0]='U';
  }
  return(fstr);
}

char *tcp_opt_str(uint8_t *opt, uint8_t optsize)
{
  static uint8_t optstr[256];
  optstr[0]   = 0;
  uint8_t  t  = 0;
  uint8_t  l  = 0;
  uint32_t d0 = 0;
  uint32_t d1 = 0;
  uint8_t buf[32];
  while(optsize){
    t = *(opt++);
    if(t == 0){
      break;    /* END */
    }
    if(t == 1){
      continue; /* NO-OP */
    }
    d0 = 0;
    d1 = 0;
    l  = *(opt++);
    switch(l-2){
      case 1:
        d0 = (uint32_t)(*((uint8_t *)opt));
        break;
      case 2:
        d0 = (uint32_t)(ntohs(*((uint16_t *)opt)));
        break;
      case 4:
        d0 = (uint32_t)(ntohl(*((uint32_t *)opt)));
        break;
      case 8:
        d0 = ntohl(*((uint32_t *)(opt + 0)));
        d1 = ntohl(*((uint32_t *)(opt + 4)));
        break;
    }
    switch(t){
      case 2:
        sprintf(buf, "mss=%u", d0);
        break;
      case 3:
        sprintf(buf, "wscale=%u", d0);
        break;
      case 4:
        sprintf(buf, "sackOK");
        break;
      case 5:
        sprintf(buf, "sack 1"); /* len = 10 */
        break;
      case 8:
        sprintf(buf, "timestamp %u %u", d0, d1);
        break;
      default:
        sprintf(buf, "len=%hhu opt[%hhu]", l, t);
        break;
    }
    opt += (l - 2);
    optsize -= l;
    if(*optstr){
      strcat(optstr, ", ");
    }
    strcat(optstr, buf);
  }
  return(optstr);
}

uint64_t get_keika_time(struct timeval *stv, struct timeval *etv)
{
  struct timeval tv;
  if(timercmp(etv, stv, <)){
    return(0);
  }
  timersub(etv, stv, &tv);
  return(tv.tv_sec * 1000000 + tv.tv_usec);
}

uint32_t tcp_connection_time(tcpsession *c)
{
  uint32_t t;
  struct timeval ct;
  timerclear(&ct);
  if((c != NULL) && (c->last != NULL)){
    timersub(&(c->last->ts), &(c->segment.ts), &ct);
  }
  t  = ct.tv_sec  * 1000;
  t += ct.tv_usec / 1000;
  return(t);
}

tcpsegment *tcp_retransmit_segment(tcpsession *c, tcpsegment *t)
{
  tcpsegment *p;
  if(c == NULL){
    return(NULL);
  }
  for(p=&(c->segment);p;p=p->next){
    if((p->seqno == t->seqno) &&
       (p->ackno == t->ackno) && 
       (p->flags == t->flags) &&
       (p->segsz == t->segsz)){
      break;  
    }
  }
  return(p);
}

int is_tcp_retransmit_ignore(tcpsegment *p1, tcpsegment *p2)
{
  int64_t delay;
  if((p1->flags & 2) != 0){
    return(opt.rsynfind == 0);
  }
  if(opt.rt_limit == 0){
    return(1);
  }
  delay  = p1->ts.tv_sec;
  delay -= p2->ts.tv_sec;
  delay *= 1000000;
  delay += p1->ts.tv_usec;
  delay -= p2->ts.tv_usec;
  delay /= 1000;
  delay  = (delay > 0) ? delay : -delay;
  return(delay < opt.rt_limit);
}

int is_tcpsession_closed(tcpsession *c){
  if(c == NULL){
    return(0);
  }
  if((c->st[0] == MIRUO_STATE_TCP_CLOSED) && (c->st[1] == MIRUO_STATE_TCP_CLOSED)){
    return(1);
  }
  if((c->st[0] == MIRUO_STATE_TCP_TIME_WAIT) && (c->st[1] == MIRUO_STATE_TCP_CLOSED)){
    return(1);
  }
  if((c->st[0] == MIRUO_STATE_TCP_CLOSED) && (c->st[1] == MIRUO_STATE_TCP_TIME_WAIT)){
    return(1);
  }
  return(0);
}

/***********************************************************************
 * ここからデバッグ用の関数だよ
***********************************************************************/
void debug_dumpdata(uint8_t *data, int size)
{
  int i;
  for(i=0;i<size;i++){
    printf("%02X ", (uint32_t)(*(data + i)));
    if((i % 16) == 15){
      printf("\n");
    }
  }
  printf("\n");
}

void debug_print_mac(char *mac)
{
  int i=0;
  printf("%02X",mac[i]);
  for(i=1;i<6;i++){
    printf(":%02X",mac[i]);
  }
}

void debug_print_iphdr(iphdr *h)
{
  int i;
  printf("======= IP HEADER =======\n");
  printf("Ver     : %hhu\n", h->ver);
  printf("IHL     : %hhu\n", h->ihl);
  printf("TOS     : %hhu\n", h->tos);
  printf("LEN     : %hu\n",  h->len);
  printf("ID      : %hu\n",  h->id);
  printf("Flags   : %hhu\n", h->flags);
  printf("Offset  : %hu\n",  h->offset);
  printf("TTL     : %hhu\n", h->ttl);
  printf("Protocol: %hhu\n", h->protocol);
  printf("Checksum: %hX\n",  h->checksum);
  printf("SrcAddr : %s\n",   inet_ntoa(h->src));
  printf("DstAddr : %s\n",   inet_ntoa(h->dst));
  for(i=0;i<(h->ihl - 20);i++){
    printf("option[%02d]: %02x\n", h->option[i]);
  }
}

void debug_print_tcphdr(tcphdr *h)
{
  char *flags = tcp_flag_str(h->flags);
  printf("======= TCP HEADER =======\n");
  printf("sport   : %hu\n",     h->sport);
  printf("dport   : %hu\n",     h->dport);
  printf("seqno   : %u\n",      h->seqno);
  printf("ackno   : %u\n",      h->ackno);
  printf("offset  : %hhu\n",    h->offset);
  printf("flags   : %s\n",      flags);
  printf("window  : %hu\n",     h->window);
  printf("checksum: 0x%04hx\n", h->checksum);
  debug_dumpdata(h->opt, h->offset - 20);
}

void debug_timer(int n)
{
  static struct timeval tv[3];
  if(n == 0){
    gettimeofday(&(tv[0]), NULL);
    return;
  }
  gettimeofday(&(tv[1]), NULL);
  timersub(&(tv[1]), &(tv[0]), &(tv[2]));
  fprintf(stderr, "debug time=%d.%06d\n", tv[2].tv_sec, tv[2].tv_usec);
}
/***********************************************************************
 * ここまでデバッグ用の関数だよ
***********************************************************************/

uint8_t *read_header_eth(ethhdr *h, uint8_t *p, uint32_t *l)
{
  if(*l < sizeof(ethhdr)){
    opt.err_l2++;
    return(NULL);
  }
  memcpy(h, p, sizeof(ethhdr));
  h->type = ntohs(h->type);
  p  += sizeof(ethhdr);
  *l -= sizeof(ethhdr);
  return(p);
}

uint8_t *read_header_sll(sllhdr *h, uint8_t *p, uint32_t *l)
{
  if(*l < sizeof(sllhdr)){
    opt.err_l2++;
    return(NULL);
  }
  memcpy(h, p, sizeof(sllhdr));
  h->type = ntohs(h->type);
  p  += sizeof(sllhdr);
  *l -= sizeof(sllhdr);
  return(p);
}

uint8_t *read_header_l2(l2hdr *h, int lktype, uint8_t *p, uint32_t *l){
  switch(lktype){
    case DLT_EN10MB:
      return read_header_eth(&(h->hdr.eth), p, l);
    case DLT_LINUX_SLL:
      return read_header_sll(&(h->hdr.sll), p, l);
  }
  return(NULL);
}

#if defined(__APPLE__) && defined(DLT_PKTAP)
#include <net/if.h>
#include <sys/param.h>
#define PKTAP_IFXNAMESIZE (IF_NAMESIZE + 8)
/*
 * Header for DLT_PKTAP
 *
 * In theory, there could be several types of blocks in a chain before the actual packet
 */
struct pktap_header {
    uint32_t    pth_length;             /* length of this header */
    uint32_t    pth_type_next;          /* type of data following */
    uint32_t    pth_dlt;                /* DLT of packet */
    char        pth_ifname[PKTAP_IFXNAMESIZE];  /* interface name */
    uint32_t    pth_flags;              /* flags */
    uint32_t    pth_protocol_family;
    uint32_t    pth_frame_pre_length;
    uint32_t    pth_frame_post_length;
    pid_t       pth_pid;                /* process ID */
    char        pth_comm[MAXCOMLEN+1];  /* process command name */
    uint32_t    pth_svc;                /* service class */
    uint16_t    pth_iftype;
    uint16_t    pth_ifunit;
    pid_t       pth_epid;       /* effective process ID */
    char        pth_ecomm[MAXCOMLEN+1]; /* effective command name */
};
#endif

uint8_t *read_header_ip(iphdr *h, uint8_t *p, uint32_t *l)
{
  int optlen;
  iphdraw *hr;
  int lktype;
  lktype = opt.lktype;
#if defined(__APPLE__) && defined(DLT_PKTAP)
  if(lktype == DLT_PKTAP){ // Apple PKTAP
    struct pktap_header *pth;
    pth = (struct pktap_header *)p;
    p  += pth->pth_length;
    *l -= pth->pth_length;
    lktype = pth->pth_dlt;
    if(pth->pth_protocol_family != PF_INET){
      return(NULL);
    }
  }
#endif
  switch(lktype){
    case DLT_RAW:  // RAW IP
      hr = (iphdraw *)p;
      break;
    case DLT_NULL: // BSD Loopback
      if(*((uint32_t *)p) != PF_INET){
        return(NULL);
      }
      p  += 4;
      *l -= 4;
      hr = (iphdraw *)p;
      break;
    case DLT_LOOP: // OpenBSD Loopback
      if(*((uint32_t *)p) != htonl(PF_INET)){
        return(NULL);
      }
      p  += 4;
      *l -= 4;
      hr = (iphdraw *)p;
      break;
    default: // Ethernet or Linux SLL
      hr = (iphdraw *)(p = read_header_l2(&(h->l2), lktype, p, l));
      if(hr == NULL){
        return(NULL);
      }
      if(get_l3type(&(h->l2)) != 0x0800){
        return(NULL); // IP以外は破棄
      }
  }
  if(*l < sizeof(iphdraw)){
    opt.err_ip++;
    return(NULL); // 不完全なデータ
  }
  h->ver        = (hr->vih & 0xf0) >> 4;
  h->ihl        = (hr->vih & 0x0f) << 2;
  h->tos        = hr->tos;
  h->len        = ntohs(hr->len);
  h->id         = ntohs(hr->id);
  h->flags      = ntohs(hr->ffo) >> 13;
  h->offset     = ntohs(hr->ffo) & 0x1fff;
  h->ttl        = hr->ttl;
  h->protocol   = hr->protocol;
  h->checksum   = ntohs(hr->checksum);
  h->src.s_addr = hr->src;
  h->dst.s_addr = hr->dst;
  p  += sizeof(iphdraw);
  *l -= sizeof(iphdraw);
  if(optlen = h->ihl - sizeof(iphdraw)){
    if(*l < optlen){
      return(NULL);
    }
    memcpy(h->option, p, optlen);
    p  += optlen;
    *l -= optlen;
  }  
  return(p);
}

u_char *read_header_tcp(tcphdr *h, uint8_t *p, uint32_t *l)
{
  tcphdraw *hr;
  p= read_header_ip(&(h->ip), p, l);
  hr = (tcphdraw *)p;
  if(hr == NULL){
    return(NULL);
  }
  if(h->ip.offset != 0){
    return(NULL); // フラグメントの先頭以外は破棄
  }
  if(h->ip.protocol != 6){
    return(NULL); // TCP以外は破棄
  }
  if(*l < 20){
    opt.err_tcp++;
    return(NULL);
  }
  h->sport    = ntohs(hr->sport); 
  h->dport    = ntohs(hr->dport); 
  h->seqno    = ntohl(hr->seqno); 
  h->ackno    = ntohl(hr->ackno); 
  h->offset   = hr->offset >> 2;
  h->flags    = hr->flags;
  h->window   = ntohs(hr->window);
  h->checksum = ntohs(hr->checksum);
  h->urgent   = ntohs(hr->urgent);
  if(*l < h->offset){
    opt.err_tcp++;
    return(NULL);
  }
  memcpy(h->opt, hr->opt, h->offset - 20);
  p  += h->offset;
  *l -= h->offset;
  return(p);
}

tcpsession *get_active_tcpsession(tcpsession *session)
{
  tcpsession *c;
  session->segment.sno = 0;
  session->segment.rno = 1;
  for(c=opt.tsact;c;c=c->next){
    if((memcmp(&(c->ip[0]), &(session->ip[0]), sizeof(struct sockaddr_in)) == 0) && 
       (memcmp(&(c->ip[1]), &(session->ip[1]), sizeof(struct sockaddr_in)) == 0)){
      break;
    }
    if((memcmp(&(c->ip[0]), &(session->ip[1]), sizeof(struct sockaddr_in)) == 0) && 
       (memcmp(&(c->ip[1]), &(session->ip[0]), sizeof(struct sockaddr_in)) == 0)){
      session->segment.sno = 1;
      session->segment.rno = 0;
      break;
    }
  }
  return(c);
}

/*************************************************
*
* tcpsegmentの生成/開放
*
*************************************************/
tcpsegment *malloc_tcpsegment_pool()
{
  if(opt.sg_limit && (opt.count_sg_act >= opt.sg_limit)){
    opt.count_sg_drop++;
    return(NULL);
  }
  return(malloc(sizeof(tcpsegment)));

  int i;
  tcpsegment *tp;
  if(opt.tsegpool.free == NULL){
    opt.tsegpool.count = 32768;
    opt.tsegpool.pool  = realloc(opt.tsegpool.pool, sizeof(tcpsegment *) * (opt.tsegpool.block + 1));
    opt.tsegpool.free  = malloc(sizeof(tcpsegment) * opt.tsegpool.count);
    opt.tsegpool.pool[opt.tsegpool.block] = opt.tsegpool.free;
    for(i=1;i<opt.tsegpool.count;i++){
      opt.tsegpool.pool[opt.tsegpool.block][i-1].next = &(opt.tsegpool.pool[opt.tsegpool.block][i]);
      opt.tsegpool.pool[opt.tsegpool.block][i].prev = &(opt.tsegpool.pool[opt.tsegpool.block][i-1]);
    }
    opt.tsegpool.block++;
  }

  tp = opt.tsegpool.free;
  if(opt.tsegpool.free = tp->next){
    tp->next->prev = NULL;
    tp->next = NULL;
  }
  return(tp);
}

void free_tcpsegment_pool(tcpsegment *packet)
{
  if(packet == NULL){
    return;
  }
  lnklist_destroy_with_destructor(packet->dpimsg, free);
  free(packet);
  return;
  packet->prev = NULL;
  packet->next = opt.tsegpool.free;
  opt.tsegpool.free = packet;
}

tcpsegment *malloc_tcpsegment(tcpsegment *s)
{
  tcpsegment *n = malloc_tcpsegment_pool();
  if(n == NULL){
    opt.count_sg_drop++;
    return(NULL);
  }
  if(s){
    memcpy(n, s, sizeof(tcpsegment));
  }else{
    memset(n, 0, sizeof(tcpsegment));
  }
  opt.count_sg_act++;
  if(opt.count_sg_act > opt.count_sg_max){
    opt.count_sg_max = opt.count_sg_act;
  }
  return(n);
}

void free_tcpsegment(tcpsegment *packet)
{
  if(packet == NULL){
    return;
  }
  if(packet->prev){
    packet->prev->next = packet->next;
  }
  if(packet->next){
    packet->next->prev = packet->prev;
  }
  free_tcpsegment_pool(packet);
  opt.count_sg_act--;
}

tcpsegment *add_tcpsegment(tcpsession *c, tcpsegment *t)
{
  tcpsegment *r;
  tcpsegment *p;
  if(c == NULL){
    return(NULL);
  }
  t = malloc_tcpsegment(t);
  if(t == NULL){
    return(NULL);
  }
  p = (c->last) ? c->last : &(c->segment);
  c->pkcnt++;
  c->pkall++;
  c->szall += t->segsz;
  p->next  = t;
  c->last  = t;
  t->prev  = p;
  t->segno = p->segno + 1;
  t->st[0] = c->st[t->sno];
  t->st[1] = c->st[t->rno];

  if(opt.fragment && (t->fragment & 1)){
    c->view  = 1;
    t->view  = 0;
    t->color = COLOR_RED;
    opt.count_ip_fragment++;
  }
  if((opt.st_limit > 0) && ((get_keika_time(&(p->ts), &(t->ts)) / 1000) > opt.st_limit)){
    c->view  = 1;
    p->view  = 0;
    t->view  = 0;
    t->color = COLOR_RED;
    opt.count_sg_delay++;
  }
  if(opt.live == 1){
    t->view = 0;
  }else{
    t->view = (t->color == 0);
  }
  if(c->pkcnt > 2048){
    p = c->segment.next;
    while(p){
      if(p->view == 0){
        p = p->next;
        continue;
      }
      if(p->prev){
        p->prev->next = p->next;
      }
      if(p->next){
        p->next->prev = p->prev;
      }
      if(c->last == p){
        c->last = p->prev;
      }
      r = p->next;
      p->prev = NULL;
      p->next = NULL;
      free_tcpsegment(p);
      p = r;
      c->pkcnt--;
      if(c->pkcnt < 1024){
        break;
      }
    }
  }
  return(t);
}

/*************************************************
*
* tcpsessionの生成/開放
*
*************************************************/
tcpsession *malloc_tcpsession(tcpsession *c)
{
  tcpsession *s;
  static uint16_t sid = 0;
  if(s = opt.tsespool.free){
    if(opt.tsespool.free = s->next){
      s->next->prev = NULL;
      s->next = NULL;
    }
    opt.tsespool.count--;
  }else{
    if(s = malloc(sizeof(tcpsession))){
      opt.count_ts++;
    }else{
      return(NULL);
    }
  }
  if(c){
    memcpy(s, c, sizeof(tcpsession));
  }else{
    memset(s, 0, sizeof(tcpsession));
  }
  s->sid   = sid = (sid > 9999) ? 1 : sid + 1;
  s->pkcnt = 1;
  s->pkall = 1;
  return(s);
}

void free_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  while(c->segment.next){
    tcpsegment *p = c->segment.next->next;
    free_tcpsegment(c->segment.next);
    c->segment.next = p; 
  }
  c->last  = NULL;
  c->pkcnt = 1;
  if(c->prev){
    c->prev->next = c->next;
  }
  if(c->next){
    c->next->prev = c->prev;
  }
  if(opt.tsespool.count >= 65535){
    free(c);
    opt.count_ts--;
  }else{
    if(c->next = opt.tsespool.free){
      c->next->prev = c;
    }
    opt.tsespool.free = c;
    opt.tsespool.count++;
  }
}

tcpsession *del_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return(NULL);
  }
  tcpsession *p = c->prev; 
  tcpsession *n = c->next;
  if(c == opt.tsact){
    if(opt.tsact = n){
      opt.tsact->prev = NULL;
    }
  }else{
    if(p){
      p->next = n;
    }
    if(n){
      n->prev = p;
    }
  }
  opt.count_ts_act--;
  free_tcpsession(c);
  return(n);
}

tcpsession *add_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return(NULL);
  }
  if(c->segment.flags != 2){
    return(NULL);
  }

  if(opt.ts_limit && (opt.count_ts_act >= opt.ts_limit)){
    opt.count_ts_drop++;
    return(NULL);
  }

  c = malloc_tcpsession(c);
  if(c == NULL){
    return(NULL);
  }
  if(c->next = opt.tsact){
    c->next->prev = c;
  }
  opt.tsact = c;
  opt.count_ts_act++;
  opt.count_ts_total++;
  if(opt.count_ts_max < opt.count_ts_act){
    opt.count_ts_max = opt.count_ts_act;
  }
  return(c);
}

/********************************************************************
*
* 描画関係
*
********************************************************************/
void print_acttcpsession(FILE *fp)
{
  struct tm *t;
  uint64_t  td;
  char st[256];
  char ts[2][64];
  char ip[2][64];
  tcpsession  *c;
  for(c=opt.tsact;c;c=c->next){
    t = localtime(&(c->segment.ts.tv_sec));
    sprintf(st,    "%s/%s", tcp_state_str(c->st[0]), tcp_state_str(c->st[1]));
    sprintf(ts[0], "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, c->segment.ts.tv_usec / 1000);
    sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
    sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
    td = 0;
    if(c->last){
      td  = c->last->ts.tv_sec - c->segment.ts.tv_sec;
      td *= 1000;
      td += c->last->ts.tv_usec  / 1000;
      td -= c->segment.ts.tv_usec / 1000;
    }
    sprintf(ts[1], "%u.%03us", (int)(td/1000), (int)(td%1000));
    fprintf(fp, "%04d %s(+%s) %s %s %-23s\n", c->pkcnt, ts[0], ts[1], ip[0], ip[1], st);
  }
}

void print_dpimsg(FILE *fp, tcpsegment *sg)
{
  char cl[2][16];

  cl[0][0] = 0;
  cl[1][0] = 0;
  if(opt.color){
    sprintf(cl[0], "\x1b[3%dm", COLOR_GREEN);
    sprintf(cl[1], "\x1b[39m");
  }
  if(sg && sg->dpimsg){
    switch(opt.mode){
      case MIRUO_MODE_TCP:
        break;
      case MIRUO_MODE_HTTP:
        lnklist_iter_init(sg->dpimsg);
        while(lnklist_iter_hasnext(sg->dpimsg)){
          fprintf(fp, "%s%s%s\n", cl[0], lnklist_iter_next(sg->dpimsg), cl[1]);
        }
        break;
    }
  }
}

void print_tcpsession(FILE *fp, tcpsession *c)
{
  struct tm *t;               //
  char st[64];                // TCPステータス
  char ts[32];                // タイムスタンプ
  char fs[32];                // IPフラグメント文字列
  char cl[2][16];             // 色指定用ESCシーケンス
  char ip[2][64];             // IPアドレス
  char *allow[] = {">", "<"}; //
  tcpsegment *sg;

  if(c == NULL){
    return;
  }
  if(c->view == 0){
    return;
  }
 
  fs[0]    = 0; 
  cl[0][0] = 0;
  cl[1][0] = 0;
  if(opt.color){
    sprintf(cl[0], "\x1b[3%dm", COLOR_YELLOW);
    sprintf(cl[1], "\x1b[39m");
  }
  if(opt.live == 0){
    uint32_t ct = tcp_connection_time(c);
    sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
    sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
    if(opt.quiet){
      fprintf(fp, "%s%8u.%03u|%21s == %-21s|%useg(%u)%s\n",
        cl[0],
          ct / 1000,
          ct % 1000,
          ip[0],
          ip[1], 
          c->pkall,
          c->szall, 
        cl[1]);
    }else{
      fprintf(fp, "%s%04u %13u.%03u |%21s == %-21s| Total %u segments, %u bytes%s\n",
        cl[0],
          c->sid, 
          ct / 1000,
          ct % 1000,
          ip[0], ip[1], 
          c->pkall, c->szall, 
        cl[1]);
    }
  }
  for(sg=&(c->segment);sg;sg=sg->next){
    if(sg->view){
      continue;
    }
    cl[0][0] = 0;
    cl[1][0] = 0;
    if(sg->color && opt.color){
      sprintf(cl[0], "\x1b[3%dm", sg->color);
      sprintf(cl[1], "\x1b[39m");
    }
    t = localtime(&(sg->ts.tv_sec));
    sprintf(ts, "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, sg->ts.tv_usec / 1000);
    if(opt.fragment){
      if((sg->fragment & 1) != 0){
        sprintf(fs, "F");
      }else{
        sprintf(fs, "-");
      }
    }
    if(opt.live == 0){
      if(opt.quiet){
        fprintf(fp, "%s%s|%18s %s%s%s %-18s|%08X/%08X%s\n",
          cl[0], 
            ts, 
            tcp_state_str(sg->st[sg->sno]),
            allow[sg->sno], tcp_flag_str(sg->flags), allow[sg->sno],  
            tcp_state_str(sg->st[sg->rno]),
            sg->seqno, 
            sg->ackno,
          cl[1]);
        print_dpimsg(fp, sg);
        if(sg->next && sg->next->view){
          fprintf(fp, "%12s|%46s|\n", "", "");
        }
      }else{
        fprintf(fp, "%s%04u:%04u %s |%18s %s%s%s %-18s| %08X/%08X %4u %s <%s>%s\n",
          cl[0], 
            c->sid, sg->segno,
            ts, 
            tcp_state_str(sg->st[sg->sno]),
            allow[sg->sno], tcp_flag_str(sg->flags), allow[sg->sno],  
            tcp_state_str(sg->st[sg->rno]),
            sg->seqno, sg->ackno,
            sg->segsz,
            fs,
            tcp_opt_str(sg->opt, sg->optsize), 
          cl[1]);
        print_dpimsg(fp, sg);
        if(sg->next && sg->next->view){
          fprintf(fp, "%04u:**** %12s |%46s|\n", c->sid, "", "");
        }
      }
    }else{
      sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
      sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
      sprintf(st, "%s/%s", tcp_state_str(sg->st[sg->sno]), tcp_state_str(sg->st[sg->rno]));
      fprintf(fp, "%s%04u:%04u %s %s %s%s%s %s %-23s %08X/%08X %4u %s <%s>%s\n",
        cl[0], 
          c->sid, sg->segno,
          ts,
          ip[0],
          allow[sg->sno], tcp_flag_str(sg->flags), allow[sg->sno],  
          ip[1],
          st,
          sg->seqno, 
          sg->ackno,
          sg->segsz,
          fs,
          tcp_opt_str(sg->opt, sg->optsize), 
        cl[1]);
      print_dpimsg(fp, sg);
    }
    sg->view = 1;
  }
}

void miruo_tcpsession_statistics(int view)
{
  char tstr[32];
  uint32_t  cpu;
  uint64_t  ctm;
  meminfo   *mi;
  struct pcap_stat ps;
  static struct timeval viewtime={0, 0};

  if(view == 0){
    if(opt.stattime == 0){
      return;
    }
    if(viewtime.tv_sec){
      if(get_keika_time(&viewtime, &(opt.ntv)) / 1000000 < opt.stattime){
        return;
      }
    }
  }
  viewtime.tv_sec  = opt.ntv.tv_sec;
  viewtime.tv_usec = opt.ntv.tv_usec;
  /*
  if(opt.tsact){
    fprintf(stderr, "===== ACTIVE SESSIONLIST =====\n");
    print_acttcpsession(stderr);
  }
  */
  memset(&ps, 0, sizeof(ps));
  pcap_stats(opt.p, &ps);
  cpu = get_cpu_utilization();
  ctm = get_keika_time(&(opt.stv), &(opt.ntv)) / 1000000;
  sprintf(tstr, "%02d:%02d:%02d", ctm/3600, (ctm % 3600)/60, ctm % 60);
  fprintf(stderr, "\n");
  fprintf(stderr, "===== Session Statistics =====\n");
  fprintf(stderr, "Captcha Time    : %s\n",   tstr);
  fprintf(stderr, "Total Sessions  : %llu\n", opt.count_ts_total);
  fprintf(stderr, "  Lookup        : %llu\n", opt.count_ts_view);
  fprintf(stderr, "    LongConnect : %llu\n", opt.count_ts_long);
  fprintf(stderr, "    LongDelay   : %llu\n", opt.count_sg_delay);
  fprintf(stderr, "    Retransmit  : %llu\n", opt.count_sg_retrans);
  fprintf(stderr, "    Timeout     : %llu\n", opt.count_ts_timeout);
  fprintf(stderr, "    Error       : %llu\n", opt.count_ts_error);
  fprintf(stderr, "    RST         : %llu\n", opt.count_rstbreak + opt.count_rstclose);
  fprintf(stderr, "    fragment    : %llu\n", opt.count_ip_fragment);
  fprintf(stderr, "------------------------------\n");
  fprintf(stderr, "LongConnectTime : %d [ms]\n", opt.ct_limit);
  fprintf(stderr, "LongDelayTime   : %d [ms]\n", opt.st_limit);
  fprintf(stderr, "RetransmitTime  : %d [ms]\n", opt.rt_limit);
  fprintf(stderr, "------------------------------\n");
  fprintf(stderr, "ActiveSession   : %u\n",   opt.count_ts_act);
  fprintf(stderr, "ActiveSessionMax: %u\n",   opt.count_ts_max);
  fprintf(stderr, "ActiveSessionLim: %u\n",   opt.ts_limit);
  fprintf(stderr, "ActiveSegment   : %u\n",   opt.count_sg_act);
  fprintf(stderr, "ActiveSegmentMax: %u\n",   opt.count_sg_max);
  fprintf(stderr, "ActiveSegmentLim: %u\n",   opt.sg_limit);
  fprintf(stderr, "DropSession     : %u\n",   opt.count_ts_drop);
  fprintf(stderr, "DropSegment     : %u\n",   opt.count_sg_drop);
  fprintf(stderr, "------------------------------\n");
  fprintf(stderr, "CPU   : %u.%u%%\n", cpu/10, cpu%10);
if(mi = get_memmory()){
  fprintf(stderr, "VSZ   : %lluKB\n",  mi->vsz / 1024);
  fprintf(stderr, "RSS   : %lluKB\n",  mi->res / 1024);
}
if(pcap_fileno(opt.p)){
  fprintf(stderr, "===== libpcap Statistics =====\n");
  fprintf(stderr, "recv  : %u\n", ps.ps_recv);
  fprintf(stderr, "drop  : %u\n", ps.ps_drop);
  fprintf(stderr, "ifdrop: %u\n", ps.ps_ifdrop);
  fprintf(stderr, "===== Header Error Count =====\n");
  fprintf(stderr, "L2    : %d\n", opt.err_l2);
  fprintf(stderr, "IP    : %d\n", opt.err_ip);
  fprintf(stderr, "TCP   : %d\n", opt.err_tcp);
}
  fprintf(stderr, "==============================\n");
}

tcpsession *miruo_tcpsession_destroy(tcpsession *c, int view, char *msg, char *reason)
{
  int  l;
  int  r;
  char sl[32];
  char sr[32];
  char ts[32];
  char sc[2][8];
  struct tm *tm;

  if(c->view = view){
    opt.count_ts_view++;
    print_tcpsession(stdout, c);
    l  = 46 - strlen(msg);
    r  = l / 2;
    l -= r;
    memset(sl, 0, sizeof(sl));
    memset(sr, 0, sizeof(sr));
    memset(sl, ' ', l);
    memset(sr, ' ', r);
    if(opt.color){
      sprintf(sc[0], "\x1b[31m");
      sprintf(sc[1], "\x1b[39m");
    }else{
      sc[0][0] = 0;
      sc[1][1] = 0;
    }
    tm = localtime(&(opt.ntv.tv_sec));
    sprintf(ts, "%02d:%02d:%02d.%03u", tm->tm_hour, tm->tm_min, tm->tm_sec, opt.ntv.tv_usec/1000);
    if(opt.live){
      fprintf(stdout, "%s%04u:%04u %s %s (%s)%s\n", sc[0], c->sid, c->pkcnt, ts, msg, reason, sc[1]);
    }else{
      if(opt.quiet){
        fprintf(stdout, "%s%s|%s%s%s|%s%s\n", sc[0], ts, sl, msg, sr, reason, sc[1]);
      }else{
        fprintf(stdout, "%s%04u:%04u %s |%s%s%s| %s%s\n", sc[0], c->sid, c->pkcnt, ts, sl, msg, sr, reason, sc[1]);
      }
    }
  }
  return(del_tcpsession(c));
}

void miruo_tcpsession_timeout()
{
  int d;
  tcpsession *c;
  tcpsegment *s;

  c = opt.tsact;
  while(c){
    s = c->last ? c->last : &(c->segment);
    d = opt.ntv.tv_sec - s->ts.tv_sec;
    if(d > 900){
      opt.count_ts_timeout++;
      c = miruo_tcpsession_destroy(c, 1, "destroy session", "time out");
      continue;
    }
    if(d > 30){
      switch(c->st[0]){
        case MIRUO_STATE_TCP_SYN_SENT:
        case MIRUO_STATE_TCP_SYN_RECV:
        case MIRUO_STATE_TCP_FIN_WAIT1:
        case MIRUO_STATE_TCP_FIN_WAIT2:
        case MIRUO_STATE_TCP_CLOSE_WAIT:
        case MIRUO_STATE_TCP_LAST_ACK:
          opt.count_ts_timeout++;
          c = miruo_tcpsession_destroy(c, 1, "destroy session", "time out");
          continue;
      }
      switch(c->st[1]){
        case MIRUO_STATE_TCP_SYN_SENT:
        case MIRUO_STATE_TCP_SYN_RECV:
        case MIRUO_STATE_TCP_FIN_WAIT1:
        case MIRUO_STATE_TCP_FIN_WAIT2:
        case MIRUO_STATE_TCP_CLOSE_WAIT:
        case MIRUO_STATE_TCP_LAST_ACK:
          opt.count_ts_timeout++;
          c = miruo_tcpsession_destroy(c, 1, "destroy session", "time out");
          continue;
      }
    }
    s = c->segment.next;
    while(s){
      if(s->view){
        // 再送時間の最長を暫定的に30秒として、それ以前に受け取ったセグメントを破棄する。
        // この処理の目的は、メモリを節約することと、セッション開放時の処理を軽減させること。
        // そのため30秒以内の再送は検出できるがそれ以上かかった場合は検知できなくなる。
        // まあ、30秒でも十分に大きすぎる気がするのでRTOをざっくり計算したほうがいいのかな。
        if((opt.ntv.tv_sec - s->ts.tv_sec) > 30){
        }
      }
      s = s->next;
    }
    c = c->next;
  }
}

int tcp_retransmit(tcpsession *c, tcpsegment *t)
{
  tcpsegment *p;
  if(p = tcp_retransmit_segment(c, t)){
    // p = 再送元のセグメント
    // t = 再送したセグメント
    if(is_tcp_retransmit_ignore(p, t)){
      return(1);
    }
    c->view = 1;
    if((p->optsize != t->optsize) || (memcmp(p->opt, t->opt, p->optsize) != 0)){
      t->color = COLOR_MAGENTA;
    }else{
      t->color = COLOR_RED;
    }
    if(opt.live == 0){
      p->view  = 0;
      p->color = COLOR_GREEN;
      p = p->next;
      while(p){
        if(p->color == 0){
          p->view  = 0;
          p->color = COLOR_CYAN;
        }
        p = p->next;
      }
    }
  }
  return(0);
}

tcpsession *miruo_tcpsession_connect(tcpsession *c, tcpsession *s, int *connect)
{
  if(s->segment.flags != 2){
    return(c);
  }
  if(c == NULL){
    if(c = add_tcpsession(s)){
      *connect = 1;
      c->segment.color = COLOR_YELLOW;
    }else{
      return(NULL);
    }
  }else{
    if((c->segment.seqno == s->segment.seqno) && 
       (c->segment.ackno == s->segment.ackno)){
      return(c);
    }
    opt.count_ts_error++;
    miruo_tcpsession_destroy(c, (opt.quiet < 2), "error break", "Duplicate connection(packet loss?)");
    if(c = add_tcpsession(s)){
      *connect = 1;
      if(opt.quiet < 1){
        c->segment.color = COLOR_RED;
        c->view = 1;
      }else{
        c->segment.color = COLOR_YELLOW;
        c->view = 0;
      }
    }else{
      return(NULL);
    }
  }
  c->st[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->st[1] = MIRUO_STATE_TCP_SYN_RECV;
  c->segment.sno = 0;
  c->segment.rno = 1;
  c->segment.st[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->segment.st[1] = MIRUO_STATE_TCP_SYN_RECV;
  return(c);
}

int miruo_tcpsession_close(tcpsession *c){
  if(!is_tcpsession_closed(c)){
    return(0);
  }
  if(opt.live){
    c->view = 1;
  }
  if(opt.all){
    c->view = 1;
  }
  if((opt.ct_limit > 0) && (tcp_connection_time(c) > opt.ct_limit)){
    c->view = 1;
    opt.count_ts_long++;
  }
  if(c->view){
    opt.count_ts_view++;
  }
  print_tcpsession(stdout, c);
  del_tcpsession(c);
  return(1);
}

void miruo_tcp_synack(tcpsegment *s)
{
  switch(s->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      break;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_SYN_SENT:
      s->view  = 0;
      s->st[1] = MIRUO_STATE_TCP_EST;
      s->color = COLOR_YELLOW;
      break;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
}

void miruo_tcp_ack(tcpsegment *s)
{
  switch(s->st[0]){
    case MIRUO_STATE_TCP_EST:
      if(s->st[1] == MIRUO_STATE_TCP_FIN_WAIT1){
        s->st[0] = MIRUO_STATE_TCP_CLOSE_WAIT;
        s->view  = 0;
      }
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      if(s->st[1] == MIRUO_STATE_TCP_LAST_ACK){
        s->st[0] = MIRUO_STATE_TCP_TIME_WAIT;
        s->view  = 0;
      }
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_SYN_RECV:
      s->st[1] = MIRUO_STATE_TCP_EST;
      s->color = COLOR_YELLOW;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      s->st[1] = MIRUO_STATE_TCP_FIN_WAIT2;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      break;
    case MIRUO_STATE_TCP_LAST_ACK:
      s->st[1] = MIRUO_STATE_TCP_CLOSED;
      s->view  = 0;
      break;
  }
  if((s->st[0] == MIRUO_STATE_TCP_TIME_WAIT) && (s->st[1] == MIRUO_STATE_TCP_CLOSED)){
    s->color = COLOR_BLUE;
  }
}

void miruo_tcp_fin(tcpsegment *s)
{
  switch(s->st[0]){
    case MIRUO_STATE_TCP_EST:
      s->st[0] = MIRUO_STATE_TCP_FIN_WAIT1;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      s->st[0] = MIRUO_STATE_TCP_LAST_ACK;
      s->view  = 0;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_EST:
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      s->view  = 0;
      s->st[1] = MIRUO_STATE_TCP_TIME_WAIT;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
}

void miruo_tcp_finack(tcpsegment *s)
{
  switch(s->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      s->st[0] = MIRUO_STATE_TCP_FIN_WAIT1;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_EST:
      if(s->st[1] == MIRUO_STATE_TCP_EST){
        s->st[0] = MIRUO_STATE_TCP_FIN_WAIT1;
        s->view  = 0;
      }
      if(s->st[1] == MIRUO_STATE_TCP_FIN_WAIT1){
        s->st[0] = MIRUO_STATE_TCP_LAST_ACK;
        s->view  = 0;
      }
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      s->st[0] = MIRUO_STATE_TCP_LAST_ACK;
      s->view  = 0;
      break;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_EST:
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      s->st[1] = MIRUO_STATE_TCP_FIN_WAIT2;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      break;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
  }
}

void miruo_tcp_rst(tcpsegment *s)
{
  s->st[0] = MIRUO_STATE_TCP_CLOSED;
  s->st[1] = MIRUO_STATE_TCP_CLOSED;
  s->color = COLOR_RED;
  s->view  = 0;
}

int miruo_tcpsession_setstatus(tcpsession *c, tcpsegment *s)
{
  if(c == NULL){
    return(-1);
  }
  if(s == NULL){
    return(-1);
  }
  switch(s->flags & 23){
    case 2:
      break;
    case 16:
      miruo_tcp_ack(s);
      break;
    case 18:
      miruo_tcp_synack(s);
      break;
    case 1:
      miruo_tcp_fin(s);
      break;
    case 17:
      miruo_tcp_finack(s);
      break;
    case 4:
    case 20:
      if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT1)){
        c->view = (opt.rstmode > 1);
        opt.count_rstclose++;
      }else if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT2)){
        c->view = (opt.rstmode > 1);
        opt.count_rstclose++;
      }else if((s->st[1] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[0] == MIRUO_STATE_TCP_FIN_WAIT1)){
        c->view = (opt.rstmode > 1);
        opt.count_rstclose++;
      }else if((s->st[1] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[0] == MIRUO_STATE_TCP_FIN_WAIT2)){
        c->view = (opt.rstmode > 1);
        opt.count_rstclose++;
      }else{
        opt.count_rstbreak++;
        c->view = (opt.rstmode > 0);
      }
      miruo_tcp_rst(s);
      break;
    default:
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
  if(s->dpimsg){
    s->view = 0;
  }
  c->st[s->sno] = s->st[0];
  c->st[s->rno] = s->st[1];
  return(0);
}

void miruo_tcpsession_setview(tcpsession *c, tcpsegment *s)
{
  int i;
  tcpsegment *p;
  if(c == NULL){
    return;
  }
  if(s ==NULL){
    return;
  }
  if(s->view == 0){
    c->zview = opt.viewdata;
    p = s->prev;
    i = opt.viewdata;
    while(p && i){
      i--;
      p->view = 0;
      p = p->prev;
    }
  }else{
    if(c->zview){
      c->zview--;
      s->view = 0;
    }
  }
}

tcpsession *read_tcpsession(tcpsession *c, const struct pcap_pkthdr *ph, const u_char *p)
{
  int l;
  tcphdr th;
  tcpsegment *segment;

  l = ph->caplen;
  p = read_header_tcp(&th, (u_char *)p, &l);
  if(p == NULL){
    return(NULL);
  }
  segment = &(c->segment);
  opt.ntv.tv_sec  = ph->ts.tv_sec;
  opt.ntv.tv_usec = ph->ts.tv_usec;
  if(opt.stv.tv_sec == 0){
    opt.stv.tv_sec  = ph->ts.tv_sec;
    opt.stv.tv_usec = ph->ts.tv_usec;
  }
  memset(c, 0, sizeof(tcpsession));
  memcpy(&(c->ip[0].sin_addr), &(th.ip.src), sizeof(struct in_addr));
  memcpy(&(c->ip[1].sin_addr), &(th.ip.dst), sizeof(struct in_addr));
  c->ip[0].sin_port   = th.sport;
  c->ip[1].sin_port   = th.dport;
  segment->segsz      = ph->len;
  segment->flags      = th.flags;
  segment->fragment   = th.ip.flags;
  segment->seqno      = th.seqno;
  segment->ackno      = th.ackno;
  segment->optsize    = th.offset - 20;
  segment->plen       = l;
  segment->payload    = (uint8_t *)p;
  segment->ts.tv_sec  = ph->ts.tv_sec;
  segment->ts.tv_usec = ph->ts.tv_usec;
  memcpy(segment->opt, th.opt, segment->optsize);
  return(c);
}

/************************************************
 *
 * Deep Packet Inspection
 *
 ************************************************/
char *uristrip(char *uri)
{
  char *ptr;

  ptr = strchr(uri, '?');
  if(ptr){
    *ptr = '\0';
  }
  return uri;
}

char *
strtrim(char *str) {
  char *sp, *ep;

  if(!str) {
    return NULL;
  }
  for(sp = str; *sp; sp++) {
    if(!isspace(*sp)) {
      break;
    }
  }
  for(ep = (str + strlen(str)); ep > sp; ep--) {
    if(!isspace(*(ep - 1))) {
      break;
    }
  }
  memmove(str, sp, ep - sp);
  str[ep - sp] = '\0';
  return str;
}

void miruo_dpi_probe_http(tcpsegment *sg)
{
  char buf[2048], message[1024];
  char *delim, *token, *method, *uri, *ver, *hdr, *val, *code, *msg;

  if(!sg->plen){
    return;
  }
  memset(buf, 0x00, sizeof(buf));
  strncpy(buf, sg->payload, sg->plen < sizeof(buf) ? sg->plen : sizeof(buf) - 1);
  delim = strstr(buf, "\r\n\r\n");
  if(delim){
    *delim = '\0';
  }
  if(!(token = strtok(buf, " \r\n"))){
    return;
  }
  if(strcmp(token, "GET") == 0 || strcmp(token, "POST") == 0){
    method = token;
    if(!(uri = strtok(NULL, " \r\n"))){
      return;
    }
    if(!(ver = strtok(NULL, " \r\n"))){
      return;
    }
    sg->dpimsg = lnklist_create();
    snprintf(message, sizeof(message), "DPI:HTTP:RequestLine >>>> %s %s %s", method, uristrip(uri), ver);
    lnklist_add_tail(sg->dpimsg, strdup(message));
    while((token = strtok(NULL, ":\r\n"))){
      lnklist_iter_init(dpi.http.reqhdr);
      while(lnklist_iter_hasnext(dpi.http.reqhdr)){
        hdr = lnklist_iter_next(dpi.http.reqhdr);
        if(strcmp(token, hdr) == 0 || strcmp(hdr, "%") == 0){
          val = strtrim(strtok(NULL, "\r\n"));
          if(strcmp(token, "Referer") == 0){
            uristrip(val);
          }
          snprintf(message, sizeof(message), "DPI:HTTP:Header >>>>>>>>> %s: %s", token, val ? val : "");
          lnklist_add_tail(sg->dpimsg, strdup(message));
          break;
        }
      }
    }
  }else if(strcmp(token, "HTTP/1.0") == 0 || strcmp(token, "HTTP/1.1") == 0){
    ver = token;
    if(!(code = strtok(NULL, " \r\n")) || strlen(code) != 3 || !is_numeric(code)){
      return;
    }
    msg = strtok(NULL, "\r\n");
    sg->dpimsg = lnklist_create();
    snprintf(message, sizeof(message), "DPI:HTTP:ResponseLine >>> %s %s %s", ver, code, msg ? msg : "");
    lnklist_add_tail(sg->dpimsg, strdup(message));
    while((token = strtok(NULL, ":\r\n"))){
      lnklist_iter_init(dpi.http.reshdr);
      while(lnklist_iter_hasnext(dpi.http.reshdr)){
        hdr = lnklist_iter_next(dpi.http.reshdr);
        if(strcmp(token, hdr) == 0 || strcmp(hdr, "%") == 0){
          val = strtrim(strtok(NULL, "\r\n"));
          if(strcmp(token, "Referer") == 0){
            uristrip(val);
          }
          snprintf(message, sizeof(message), "DPI:HTTP:Header >>>>>>>>> %s: %s", token, val ? val : "");
          lnklist_add_tail(sg->dpimsg, strdup(message));
          break;
        }
      }
    }
  }
  sg->plen = 0;
  sg->payload = NULL;
}

void miruo_dpi_probe(tcpsession *s, tcpsegment *sg)
{
  if(!s || s->st[0] != MIRUO_STATE_TCP_EST || s->st[1] != MIRUO_STATE_TCP_EST){
    return;
  }
  switch(opt.mode){
    case MIRUO_MODE_TCP:
      // ignore
      break;
    case MIRUO_MODE_HTTP:
      miruo_dpi_probe_http(sg);
      break;
  }
}
/************************************************
 *
 * TCPセッションモニタ
 *
 ************************************************/
void miruo_tcpsession(u_char *u, const struct pcap_pkthdr *ph, const u_char *p)
{
  int connect=0;
  tcpsession ts;
  tcpsession *c;
  tcpsegment *s;

  if(!read_tcpsession(&ts, ph, p)){
    return;
  }
  c = get_active_tcpsession(&ts);
  c = miruo_tcpsession_connect(c, &ts, &connect);
  if(connect == 0){
    miruo_dpi_probe(c, &(ts.segment));
    if(tcp_retransmit(c, &(ts.segment))){
      return;
    }
    s = add_tcpsegment(c, &(ts.segment));
    if(miruo_tcpsession_setstatus(c, s) == -1){
      return;
    }
    miruo_tcpsession_setview(c, s);
  }
  if(!miruo_tcpsession_close(c)){
    if((opt.live != 0) && (c != NULL)){
      c->view = 1;
      print_tcpsession(stdout, c);
    }
  }
}

void miruo_finish(int code)
{
  if(opt.p){
    pcap_close(opt.p);
    opt.p = NULL;
  }
  lnklist_destroy_with_destructor(dpi.http.reqhdr, free);
  lnklist_destroy_with_destructor(dpi.http.reshdr, free);
  exit(code);
}

void signal_int_handler()
{
  opt.loop = 0;
  pcap_breakloop(opt.p);
}

void signal_term_handler()
{
  opt.loop = 0;
  pcap_breakloop(opt.p);
}

void signal_handler(int n)
{
  switch(n){
    case SIGINT:
      signal_int_handler();
      break;
    case SIGTERM:
      signal_term_handler();
      break;
    case SIGPIPE:
      break;
    case SIGUSR1:
      break;
    case SIGUSR2:
      break;
    case SIGALRM:
      break;
  }
}

void miruo_init_signal()
{
  struct sigaction sig;
  memset(&sig, 0, sizeof(sig));
  sig.sa_handler = signal_handler;
  if(sigaction(SIGINT,  &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGINT\n", __func__);
    miruo_finish(1);
  }
  if(sigaction(SIGTERM, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGTERM\n", __func__);
    miruo_finish(1);
  }
  if(sigaction(SIGPIPE, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGPIPE\n", __func__);
    miruo_finish(1);
  }
  if(sigaction(SIGUSR1, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGUSR1\n", __func__);
    miruo_finish(1);
  }
  if(sigaction(SIGUSR2, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGUSR2\n", __func__);
    miruo_finish(1);
  }
  if(sigaction(SIGALRM, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGALRM\n", __func__);
    miruo_finish(1);
  }
}

int miruo_init()
{
  memset(&opt, 0, sizeof(opt));
  opt.loop     = 1;
  opt.quiet    = 0;
  opt.promisc  = 1;
  opt.viewdata = 0;
  opt.fragment = 1;
  opt.rsynfind = 1;
  opt.rstmode  = 1;
  opt.stattime = 0;
  opt.pksize   = 1522;
  opt.ct_limit = 0;
  opt.st_limit = 0;
  opt.rt_limit = 1000;
  opt.ts_limit = 1024;
  opt.sg_limit = 65536;
  opt.color    = isatty(fileno(stdout));
  opt.mode     = MIRUO_MODE_TCP;
  setvbuf(stdout, 0, _IONBF, 0);
  return 0;
}

struct option *get_optlist()
{
  static struct option opt[]={
      "help",            0, NULL, 'h',
      "version",         0, NULL, 'V',
      "all",             0, NULL, 500,
      "live",            0, NULL, 501,
      "quiet",           0, NULL, 'q',
      "fragment",        1, NULL, 'F',
      "flagment",        1, NULL, 'F',
      "color",           1, NULL, 'C',
      "syn",             1, NULL, 'S',
      "rst",             1, NULL, 'R',
      "view-data",       1, NULL, 'v',
      "limit-session",   1, NULL, 'L',
      "limit-segment",   1, NULL, 'l',
      "long-connect",    1, NULL, 'T',
      "long-delay",      1, NULL, 't',
      "retransmit",      1, NULL, 'r',
      "dpi-mode",        1, NULL, 'm',
      "stat-interval",   1, NULL, 's',
      "file",            1, NULL, 'f',
      "interface",       1, NULL, 'i',
      0, 0, 0, 0
    };
  return(opt);
}

void miruo_setopt(int argc, char *argv[])
{
  int i;
  int r;
  char *reqhdr, *reshdr, *hdr;
  while((r = getopt_long_only(argc, argv, "+hVqAF:C:S:R:v:L:l:T:t:r:m:s:f:i:", get_optlist(), NULL)) != -1){
    switch(r){
      case 500:
        opt.all = 1;
        break;
      case 501:
        opt.all  = 1;
        opt.live = 1;
        break;
      case 'h':
        usage();
        miruo_finish(0);
      case 'V':
        version();
        miruo_finish(0);
      case 'q':
        opt.quiet++;
        break;
      case 'F':
        if(is_numeric(optarg)){
          opt.fragment = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'R':
        if(is_numeric(optarg)){
          opt.rstmode = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'S':
        if(is_numeric(optarg)){
          opt.rsynfind = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'v':
        if(is_numeric(optarg)){
          opt.viewdata = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'C':
        if(is_numeric(optarg)){
          opt.color = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'L':
        if(is_numeric(optarg)){
          opt.ts_limit = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'l':
        if(is_numeric(optarg)){
          opt.sg_limit = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'T':
        if(is_numeric(optarg)){
          opt.ct_limit = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 't':
        if(is_numeric(optarg)){
          opt.st_limit = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'r':
        if(is_numeric(optarg)){
          opt.rt_limit = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 's':
        if(is_numeric(optarg)){
          opt.stattime = atoi(optarg);
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'f':
        strcpy(opt.file, optarg);
        break;
      case 'm':
        if(strcmp("tcp", optarg) == 0){
          opt.mode = MIRUO_MODE_TCP;
        }else if(strncmp("http", optarg, 4) == 0 && (!optarg[4] || optarg[4] == ':')){
          dpi.http.reqhdr = lnklist_create();
          dpi.http.reshdr = lnklist_create();
          if(optarg[4]){
            reqhdr = optarg + 5;
            reshdr = strchr(reqhdr, ':');
            if(reshdr){
              *(reshdr++) = '\0';
            }
            for(hdr = strtok(reqhdr, ","); hdr; hdr = strtok(NULL, ",")){
              lnklist_add_tail(dpi.http.reqhdr, strdup(hdr));
            }
            for(hdr = strtok(reshdr, ","); hdr; hdr = strtok(NULL, ",")){
              lnklist_add_tail(dpi.http.reshdr, strdup(hdr));
            }
          }
          lnklist_add_tail(dpi.http.reqhdr, strdup("Host"));
          opt.mode = MIRUO_MODE_HTTP;
        }else{
          usage();
          miruo_finish(1);
        }
        break;
      case 'i':
        strcpy(opt.dev, optarg);
        break;
      default:
        usage();
        miruo_finish(1);
    }
  }
  for(i=optind;i<argc;i++){
    if(strlen(opt.exp)){
      strcat(opt.exp, " ");
    }
    strcat(opt.exp, argv[i]);
  }
}

void miruo_init_pcap()
{
  const char *p;
  struct bpf_program pf;
  char errmsg[PCAP_ERRBUF_SIZE];

  if(strlen(opt.file)){
    opt.p = pcap_open_offline(opt.file, errmsg);
    if(opt.p == NULL){
      fprintf(stderr, "%s: [error] %s\n", __func__, errmsg);
      miruo_finish(1);
    }
  }else{
    if(strlen(opt.dev) == 0){
      if(p = pcap_lookupdev(errmsg)){
        strcpy(opt.dev, p);
      }else{
        fprintf(stderr,"%s. please run as root user.\n", errmsg);
        miruo_finish(1);
      }
    }
    opt.p = pcap_open_live(opt.dev, opt.pksize, opt.promisc, 1000, errmsg);
    if(opt.p == NULL){
      fprintf(stderr, "%s: [error] %s %s\n", __func__, errmsg, opt.dev);
      miruo_finish(1);
    }
  }
  if(pcap_compile(opt.p, &pf, opt.exp, 0, 0)){
    fprintf(stderr, "%s: [error] %s '%s'\n", __func__, pcap_geterr(opt.p), opt.exp);
    miruo_finish(1);
  }
  if(pcap_setfilter(opt.p, &pf)){
    fprintf(stderr, "%s: [error] %s\n", __func__, pcap_geterr(opt.p));
    miruo_finish(1);
  }

  opt.pksize = pcap_snapshot(opt.p);
  opt.lktype = pcap_datalink(opt.p);
  if(p = pcap_datalink_val_to_name(opt.lktype)){
    strcpy(opt.lkname, p);
  }
  if(p = pcap_datalink_val_to_description(opt.lktype)){
    strcpy(opt.lkdesc, p);
  }
  switch(opt.lktype){
    case DLT_EN10MB:
    case DLT_LINUX_SLL:
    case DLT_RAW:
#if defined(__APPLE__) && defined(DLT_PKTAP)
    case DLT_PKTAP:
#endif
    case DLT_NULL:
    case DLT_LOOP:
      break;
    default:
      fprintf(stderr, "%s: not support datalink %s(%s)\n", __func__, opt.lkname, opt.lkdesc);
      miruo_finish(1);
  }
}

void miruo_execute_tcpsession_offline()
{
  get_cpu_utilization();
  if(pcap_loop(opt.p, 0, miruo_tcpsession, NULL) == -1){
    fprintf(stderr, "%s: [error] %s\n", __func__, pcap_geterr(opt.p));
  }
  opt.stattime = 1;
  miruo_tcpsession_statistics(1);
}

void miruo_execute_tcpsession_live()
{
  int fd;
  int nf;
  struct timeval tv;
#ifdef HAVE_SYS_EPOLL_H
  int eh;
  struct epoll_event ev;
#else
  struct pollfd pfd;
#endif

  fd = pcap_fileno(opt.p);
#ifdef HAVE_SYS_EPOLL_H
  eh = epoll_create(1);
  if(eh == -1){
    fprintf(stderr, "%s: [error] %s\n", __func__, strerror(errno));
    return;
  }
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  if(epoll_ctl(eh, EPOLL_CTL_ADD, fd, &ev) == -1){
    fprintf(stderr, "%s: [error] %s\n", __func__, strerror(errno));
    return;
  }
#else
  pfd.fd = fd;
  pfd.events = POLLIN;
#endif
  memset(&tv, 0, sizeof(tv));
  gettimeofday(&(opt.stv), NULL);
  while(opt.loop){
    if(tv.tv_sec != opt.ntv.tv_sec){
      tv.tv_sec = opt.ntv.tv_sec;
      miruo_tcpsession_statistics(0);
      miruo_tcpsession_timeout();
    }
#ifdef HAVE_SYS_EPOLL_H
    nf = epoll_wait(eh, &ev, 1, 1);
#else
    nf = poll(&pfd, 1, 1);
#endif
    if(nf == 0){
      gettimeofday(&(opt.ntv), NULL);
    }else{
      if(pcap_dispatch(opt.p, 0, miruo_tcpsession, NULL) == -1){
        fprintf(stderr, "%s: [error] %s\n", __func__, pcap_geterr(opt.p));
        break;
      }
    }
  }
  gettimeofday(&(opt.ntv), NULL);
  miruo_tcpsession_statistics(1);
#ifdef HAVE_SYS_EPOLL_H
  close(eh);
#endif
}

void miruo_execute_tcpsession()
{
  int p = pcap_fileno(opt.p);
  if(p > 0){
    miruo_execute_tcpsession_live();
  }else{
    miruo_execute_tcpsession_offline();
  }
}

void miruo_execute()
{
  printf("listening on %s, link-type %s (%s), capture size %d bytes\n", opt.dev, opt.lkname, opt.lkdesc, opt.pksize);
  switch(opt.mode){
    case MIRUO_MODE_TCP:
    case MIRUO_MODE_HTTP:
      miruo_execute_tcpsession();
      break;
    default:
      usage();
      break;
  }
}

int main(int argc, char *argv[])
{
  miruo_init();
  miruo_setopt(argc, argv);
  miruo_init_signal();
  miruo_init_pcap();
  miruo_execute();
  miruo_finish(0);
  return(0);
}

