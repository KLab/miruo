#include "miruo.h"

miruopt opt;
void version()
{
  const char *libpcap = pcap_lib_version();
  printf("miruo version 0.9\n");
  if(libpcap){
    printf("%s\n", libpcap);
  }
}

void usage()
{
  version();
  printf("usage: miruo [option] [expression]\n");
  printf("  option\n");
  printf("   -h           # help\n");
  printf("   -V           # version\n");
  printf("   -v           # verbose\n");
  printf("   -vv          # more verbose\n");
  printf("   -vvv         # most verbose\n");
  printf("   -C0          # color off\n");
  printf("   -C1          # color on\n");
  printf("   -S0          # ignore SYN retransmit\n");
  printf("   -S1          # lookup SYN retransmit(default)\n");
  printf("   -R0          # ignore RST break\n");
  printf("   -R1          # lookup RST break (default)\n");
  printf("   -R2          # lookup RST break and close\n");
  printf("   -D num       # show data packets\n");
  printf("   -a num       # active connection limit(Default 1024)\n");
  printf("   -t time      # retransmit limit(Default 1000ms)\n");
  printf("   -T time      # long connection time(Default 0ms = off)\n");
  printf("   -s interval  # statistics view interval(Default 60sec)\n");
  printf("   -r file      # read file(for tcpdump -w)\n");
  printf("   -i interface # \n");
  printf("\n");
  printf("  expression: see man tcpdump\n");
  printf("\n");
  printf("  ex)\n");
  printf("    miruo -i eth0 -s 10 2>statistics.log\n");
  printf("    miruo -i eth0 host 192.168.0.100 and port 80\n");
  printf("    miruo -i eth0 -v -T5000 src host 192.168.0.1\n");
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
  timeradd(&(opt.now_rs.ru_stime), &(opt.now_rs.ru_utime), &nctv);
  timeradd(&(opt.old_rs.ru_stime), &(opt.old_rs.ru_utime), &octv);
  timersub(&(opt.now_tv), &(opt.old_tv), &rtv);
  timersub(&(nctv), &(octv), &ctv);
  cus  = ctv.tv_sec;
  cus *= 1000000;
  cus += ctv.tv_usec;
  rus  = rtv.tv_sec;
  rus *= 1000000;
  rus += rtv.tv_usec;
  cpu = rus ? cus * 1000 / rus : 0;
  cpu = (cpu > 1000) ? 1000 : cpu;
  memcpy(&(opt.old_tv), &(opt.now_tv), sizeof(struct timeval));
  memcpy(&(opt.old_rs), &(opt.now_rs), sizeof(struct rusage));
  return(cpu);
}

meminfo *get_memmory()
{
  int   i;
  int   f;
  char *r;
  char  buff[256];
  static meminfo mi;

  memset(buff, 0, sizeof(buff));
  mi.page_size = sysconf(_SC_PAGESIZE);
  f = open("/proc/self/statm", O_RDONLY);
  if(f == -1){
    memset(&mi, 0, sizeof(meminfo));
    return(NULL);
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

uint32_t tcp_connection_time(tcpsession *c)
{
  uint32_t t;
  struct timeval ct;
  timerclear(&ct);
  if((c != NULL) && (c->last != NULL)){
    timersub(&(c->last->ts), &(c->packet.ts), &ct);
  }
  t  = ct.tv_sec  * 1000;
  t += ct.tv_usec / 1000;
  return(t);
}

tcppacket *tcp_retransmit(tcpsession *c, tcppacket *t)
{
  tcppacket *p;
  if(c == NULL){
    return(NULL);
  }
  for(p=&(c->packet);p;p=p->next){
    if((p->seqno == t->seqno) &&
       (p->ackno == t->ackno) && 
       (p->flags == t->flags) &&
       (p->size  == t->size)){
      break;  
    }
  }
  return(p);
}

int is_tcp_retransmit_ignore(tcppacket *p1, tcppacket *p2)
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

int tcp_retransmit_process(tcpsession *c, tcppacket *t)
{
  tcppacket *p;
  if(p = tcp_retransmit(c, t)){
    // p = 再送された元のパケット
    // t = 再送パケット
    if(is_tcp_retransmit_ignore(p, t)){
      return(1);
    }
    c->view = 1;
    if((p->optsize != t->optsize) || (memcmp(p->opt, t->opt, p->optsize) != 0)){
      t->color = COLOR_MAGENTA;
    }else{
      t->color = COLOR_RED;
    }
    if(opt.verbose < 2){
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
  printf("Ver     : %hhu\n", h->Ver);
  printf("IHL     : %hhu\n", h->IHL);
  printf("TOS     : %hhu\n", h->TOS);
  printf("LEN     : %hu\n",  h->len);
  printf("ID      : %hu\n",  h->id);
  printf("Flags   : %hhu\n", h->flags);
  printf("Offset  : %hu\n",  h->offset);
  printf("TTL     : %hhu\n", h->TTL);
  printf("Protocol: %hhu\n", h->Protocol);
  printf("Checksum: %hX\n",  h->Checksum);
  printf("SrcAddr : %s\n",   inet_ntoa(h->src));
  printf("DstAddr : %s\n",   inet_ntoa(h->dst));
  for(i=0;i<(h->IHL - 20);i++){
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

uint8_t *read_header_l2(l2hdr *h, uint8_t *p, uint32_t *l){
  switch(opt.lktype){
    case DLT_EN10MB:
      return read_header_eth(&(h->hdr.eth), p, l);
    case DLT_LINUX_SLL:
      return read_header_sll(&(h->hdr.sll), p, l);
  }
  return(NULL);
}

uint8_t *read_header_ip(iphdr *h, uint8_t *p, uint32_t *l)
{
  int optlen;
  iphdraw *hr = (iphdraw *)(p = read_header_l2(&(h->l2), p, l));
  if(hr == NULL){
    return(NULL);
  }
  if(get_l3type(&(h->l2)) != 0x0800){
    return(NULL); // IP以外は破棄
  }
  if(*l < sizeof(iphdraw)){
    opt.err_ip++;
    return(NULL); // 不完全なデータ
  }
  h->Ver        = (hr->vih & 0xf0) >> 4;
  h->IHL        = (hr->vih & 0x0f) << 2;
  h->TOS        = hr->tos;
  h->len        = ntohs(hr->len);
  h->id         = ntohs(hr->id);
  h->flags      = ntohs(hr->ffo) >> 13;
  h->offset     = ntohs(hr->ffo) & 0x1fff;
  h->TTL        = hr->ttl;
  h->Protocol   = hr->protocol;
  h->Checksum   = ntohs(hr->checksum);
  h->src.s_addr = hr->src;
  h->dst.s_addr = hr->dst;
  p  += sizeof(iphdraw);
  *l -= sizeof(iphdraw);
  if(optlen = h->IHL - sizeof(iphdraw)){
    fprintf(stderr, "%s: len=%d IHL=%d, size=%d\n", __func__, optlen, h->IHL, sizeof(iphdraw));
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
  if(h->ip.Protocol != 6){
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

tcpsession *get_tcpsession(tcpsession *session)
{
  tcpsession *c;
  session->packet.sno = 0;
  session->packet.rno = 1;
  for(c=opt.tsact;c;c=c->next){
    if((memcmp(&(c->ip[0]), &(session->ip[0]), sizeof(struct sockaddr_in)) == 0) && 
       (memcmp(&(c->ip[1]), &(session->ip[1]), sizeof(struct sockaddr_in)) == 0)){
      break;
    }
    if((memcmp(&(c->ip[0]), &(session->ip[1]), sizeof(struct sockaddr_in)) == 0) && 
       (memcmp(&(c->ip[1]), &(session->ip[0]), sizeof(struct sockaddr_in)) == 0)){
      session->packet.sno = 1;
      session->packet.rno = 0;
      break;
    }
  }
  return(c);
}

/*************************************************
*
* tcppacketの生成/開放
*
*************************************************/
tcppacket *malloc_tcppacket_pool()
{
  int i;
  tcppacket *tp = malloc(sizeof(tcppacket));
  return(tp);

  if(opt.tppool.free == NULL){
    opt.tppool.count = 32768;
    opt.tppool.pool  = realloc(opt.tppool.pool, sizeof(tcppacket *) * (opt.tppool.block + 1));
    opt.tppool.free  = malloc(sizeof(tcppacket) * opt.tppool.count);
    opt.tppool.pool[opt.tppool.block] = opt.tppool.free;
    for(i=1;i<opt.tppool.count;i++){
      opt.tppool.pool[opt.tppool.block][i-1].next = &(opt.tppool.pool[opt.tppool.block][i]);
      opt.tppool.pool[opt.tppool.block][i].prev = &(opt.tppool.pool[opt.tppool.block][i-1]);
    }
    opt.tppool.block++;
  }

  tp = opt.tppool.free;
  if(opt.tppool.free = tp->next){
    tp->next->prev = NULL;
    tp->next = NULL;
  }
  return(tp);
}

void free_tcppacket_pool(tcppacket *packet)
{
  if(packet == NULL){
    return;
  }
  free(packet);
  return;
  packet->prev = NULL;
  packet->next = opt.tppool.free;
  opt.tppool.free = packet;
}

tcppacket *malloc_tcppacket(tcppacket *packet)
{
  tcppacket *tp = malloc_tcppacket_pool();
  if(packet){
    memcpy(tp, packet, sizeof(tcppacket));
  }else{
    memset(tp, 0, sizeof(tcppacket));
  }
  opt.count_tp_act++;
  return(tp);
}

void free_tcppacket(tcppacket *packet)
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
  free_tcppacket_pool(packet);
  opt.count_tp_act--;
}

tcppacket *add_tcppacket(tcpsession *c, tcppacket *t)
{
  tcppacket *r;
  tcppacket *p;
  if(c == NULL){
    return;
  }
  p = (c->last) ? c->last : &(c->packet);
  c->pkcnt++;
  c->pkall++;
  c->szall += t->size;
  c->last = malloc_tcppacket(t);
  p->next = c->last;
  p->next->prev  = p;
  p->next->pno   = p->pno + 1;
  p->next->st[0] = c->st[t->sno];
  p->next->st[1] = c->st[t->rno];
  if(c->pkcnt > 2048){
    p = c->packet.next;
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
      free_tcppacket(p);
      p = r;
      c->pkcnt--;
      if(c->pkcnt < 1024){
        break;
      }
    }
  }
  return(c->last);
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
  if(s = opt.tspool.free){
    if(opt.tspool.free = s->next){
      s->next->prev = NULL;
      s->next = NULL;
    }
    opt.tspool.count--;
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
  while(c->packet.next){
    tcppacket *p = c->packet.next->next;
    free_tcppacket(c->packet.next);
    c->packet.next = p; 
  }
  c->last  = NULL;
  c->pkcnt = 1;
  if(c->prev){
    c->prev->next = c->next;
  }
  if(c->next){
    c->next->prev = c->prev;
  }
  if(opt.tspool.count >= 65535){
    free(c);
    opt.count_ts--;
  }else{
    if(c->next = opt.tspool.free){
      c->next->prev = c;
    }
    opt.tspool.free = c;
    opt.tspool.count++;
  }
}

tcpsession *del_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
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
  opt.count_act--;
  free_tcpsession(c);
  return(n);
}

tcpsession *add_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return(NULL);
  }
  if(opt.count_act < opt.ts_limit){
    c = malloc_tcpsession(c);
  }else{
    opt.count_ts_drop++;
    return(NULL);
  }
  while(c->next){
    c = c->next;
  }
  if(c->next = opt.tsact){
    c->next->prev = c;
  }
  opt.tsact = c;
  opt.count_act++;
  opt.count_total++;
  if(opt.count_actmax < opt.count_act){
    opt.count_actmax = opt.count_act;
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
    t = localtime(&(c->packet.ts.tv_sec));
    sprintf(st,    "%s/%s", tcp_state_str(c->st[0]), tcp_state_str(c->st[1]));
    sprintf(ts[0], "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, c->packet.ts.tv_usec / 1000);
    sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
    sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
    td = 0;
    if(c->last){
      td  = c->last->ts.tv_sec - c->packet.ts.tv_sec;
      td *= 1000;
      td += c->last->ts.tv_usec  / 1000;
      td -= c->packet.ts.tv_usec / 1000;
    }
    sprintf(ts[1], "%u.%03us", (int)(td/1000), (int)(td%1000));
    fprintf(fp, "%04d %s(+%s) %s %s %-23s\n", c->pkcnt, ts[0], ts[1], ip[0], ip[1], st);
  }
}

void print_tcpsession(FILE *fp, tcpsession *c)
{
  struct tm *t;               //
  char st[256];               // TCPステータス
  char ts[256];               // タイムスタンプ
  char cl[2][16];             // 色指定用ESCシーケンス
  char ip[2][64];             // IPアドレス
  char *allow[] = {">", "<"}; //
  tcppacket *tp;

  if(c == NULL){
    return;
  }
  if(c->view == 0){
    return;
  }
  
  cl[0][0] = 0;
  cl[1][0] = 0;
  if(opt.color){
    sprintf(cl[0], "\x1b[3%dm", COLOR_YELLOW);
    sprintf(cl[1], "\x1b[39m");
  }
  if(opt.verbose < 2){
    uint32_t ct = tcp_connection_time(c);
    sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
    sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
    fprintf(fp, "%s[%04u] %13u.%03u |%21s == %-21s| Total %u pks, %u bytes%s\n",
      cl[0],
        c->sid, 
        ct / 1000,
        ct % 1000,
        ip[0], ip[1], 
        c->pkall, c->szall, 
      cl[1]);
  }
  for(tp=&(c->packet);tp;tp=tp->next){
    if(tp->view){
      continue;
    }
    cl[0][0] = 0;
    cl[1][0] = 0;
    if(tp->color && opt.color){
      sprintf(cl[0], "\x1b[3%dm", tp->color);
      sprintf(cl[1], "\x1b[39m");
    }
    t = localtime(&(tp->ts.tv_sec));
    sprintf(ts, "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, tp->ts.tv_usec / 1000);
    if(opt.verbose < 2){
      fprintf(fp, "%s[%04u:%04u] %s |%18s %s%s%s %-18s| %08X/%08X %4u <%s>%s\n",
        cl[0], 
          c->sid, tp->pno,
          ts, 
          tcp_state_str(tp->st[tp->sno]),
          allow[tp->sno], tcp_flag_str(tp->flags), allow[tp->sno],  
          tcp_state_str(tp->st[tp->rno]),
          tp->seqno, tp->ackno,
          tp->size,
          tcp_opt_str(tp->opt, tp->optsize), 
        cl[1]);
      if(tp->next && tp->next->view){
        fprintf(fp, "[%04u:****] %12s |%46s|\n", c->sid, "", "");
      }
    }else{
      sprintf(ip[0], "%s:%u", inet_ntoa(c->ip[0].sin_addr), c->ip[0].sin_port);
      sprintf(ip[1], "%s:%u", inet_ntoa(c->ip[1].sin_addr), c->ip[1].sin_port);
      sprintf(st, "%s/%s", tcp_state_str(tp->st[tp->sno]), tcp_state_str(tp->st[tp->rno]));
      fprintf(fp, "%s[%04u:%04u] %s %s %s%s%s %s %-23s %08X/%08X <%s>%s\n",
        cl[0], 
          c->sid, tp->pno,
          ts,
          ip[0],
          allow[tp->sno], tcp_flag_str(tp->flags), allow[tp->sno],  
          ip[1],
          st,
          tp->seqno, tp->ackno, 
          tcp_opt_str(tp->opt, tp->optsize), 
        cl[1]);
    }
    tp->view = 1;
  }
}

void miruo_tcp_session_statistics(int view)
{
  char tstr[32];
  char mstr[64];
  uint64_t size;
  uint32_t  cpu;
  uint32_t   sc;
  tcpsession *t;
  tcpsession *s;
  tcpsession ts;
  meminfo   *mi;
  struct pcap_stat ps; //
  static int w = 0;
  if(opt.stattime == 0){
    return;
  }
  if((w > 0) && (view == 0)){
    w -= opt.itv.it_interval.tv_sec;
    if(w > 0){
      return;
    }
  }

  w = opt.stattime;
  size = opt.count_ts * sizeof(tcpsession);
  if(size > 1024 * 1024 * 1024){
    sprintf(mstr, "%lluGB", size / 1024 / 1024 / 1024);
  }else if(size > 1024 * 1024){
    sprintf(mstr, "%lluMB", size / 1024 / 1024);
  }else if(size > 1024){
    sprintf(mstr, "%lluKB", size / 1024);
  }else{
    sprintf(mstr, "%lluB", size);
  }
  if(opt.tsact){
    fprintf(stderr, "===== ACTIVE SESSIONLIST =====\n");
    print_acttcpsession(stderr);
  }
  memset(&ps, 0, sizeof(ps));
  pcap_stats(opt.p, &ps);
  cpu = get_cpu_utilization();
  sprintf(tstr, "%02d:%02d:%02d", opt.tm.tm_hour, opt.tm.tm_min, opt.tm.tm_sec);
  fprintf(stderr, "===== Session Statistics =====\n");
  fprintf(stderr, "Current Time     : %s\n",      tstr);
  fprintf(stderr, "Total Session    : %llu\n",    opt.count_total);
  fprintf(stderr, "View Session     : %llu\n",    opt.count_view);
  fprintf(stderr, "Timeout Session  : %llu\n",    opt.count_timeout);
  fprintf(stderr, "RST Break Session: %llu\n",    opt.count_rstbreak);
  fprintf(stderr, "ActiveSession    : %u\n",      opt.count_act);
  fprintf(stderr, "ActiveSessionMax : %u\n",      opt.count_actmax);
  fprintf(stderr, "DropTCPSession   : %u\n",      opt.count_ts_drop);
  fprintf(stderr, "DropTCPPacket    : %u\n",      opt.count_tp_drop);
  fprintf(stderr, "SessionPool(use) : %u\n",      opt.count_ts - opt.tspool.count);
  fprintf(stderr, "SessionPool(free): %u\n",      opt.tspool.count);
  fprintf(stderr, "TCPPacket(use)   : %u\n",      opt.count_tp_act);
  fprintf(stderr, "CPU utilization  : %u.%u%%\n", cpu/10, cpu%10);
if(mi = get_memmory()){
  fprintf(stderr, "VmSize           : %lluKB\n", mi->vsz / 1024);
  fprintf(stderr, "VmRSS            : %lluKB\n", mi->res / 1024);
  fprintf(stderr, "VmData           : %lluKB\n", mi->res / 1024);
}
  fprintf(stderr, "===== libpcap Statistics =====\n");
  fprintf(stderr, "recv  : %u\n", ps.ps_recv);
  fprintf(stderr, "drop  : %u\n", ps.ps_drop);
  fprintf(stderr, "ifdrop: %u\n", ps.ps_ifdrop);
  fprintf(stderr, "===== Error Count Report =====\n");
  fprintf(stderr, "L2    : %d\n", opt.err_l2);
  fprintf(stderr, "IP    : %d\n", opt.err_ip);
  fprintf(stderr, "TCP   : %d\n", opt.err_tcp);
  fprintf(stderr, "==============================\n");
}

tcpsession *miruo_tcp_session_destroy(tcpsession *c, char *msg, char *reason)
{
  int  l;
  int  r;
  char sl[32];
  char sr[32];
  char ts[32];
  char sc[2][8];

  c->view = 1;
  opt.count_view++;
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
  sprintf(ts, "%02d:%02d:%02d.%03u", opt.tm.tm_hour, opt.tm.tm_min, opt.tm.tm_sec, opt.now_tv.tv_usec/1000);
  if(opt.verbose < 2){
    fprintf(stdout, "%s[%04u:%04u] %s |%s%s%s| %s%s\n", sc[0], c->sid, c->pkcnt, ts, sl, msg, sr, reason, sc[1]);
  }else{
    fprintf(stdout, "%s[%04u:%04u] %s %s (%s)%s\n", sc[0], c->sid, c->pkcnt, ts, msg, reason, sc[1]);
  }
  return(del_tcpsession(c));
}

void miruo_tcp_session_timeout()
{
  tcppacket  *p;
  tcpsession *t;

  t = opt.tsact;
  if(t == NULL){
    return;
  }
  while(t){
    if((opt.now_tv.tv_sec - t->packet.ts.tv_sec) > 30){
      switch(t->st[0]){
        case MIRUO_STATE_TCP_SYN_SENT:
        case MIRUO_STATE_TCP_SYN_RECV:
        case MIRUO_STATE_TCP_FIN_WAIT1:
        case MIRUO_STATE_TCP_FIN_WAIT2:
        case MIRUO_STATE_TCP_CLOSE_WAIT:
        case MIRUO_STATE_TCP_LAST_ACK:
          opt.count_timeout++;
          t = miruo_tcp_session_destroy(t, "destroy session", "time out");
          continue;
      }
      switch(t->st[1]){
        case MIRUO_STATE_TCP_SYN_SENT:
        case MIRUO_STATE_TCP_SYN_RECV:
        case MIRUO_STATE_TCP_FIN_WAIT1:
        case MIRUO_STATE_TCP_FIN_WAIT2:
        case MIRUO_STATE_TCP_CLOSE_WAIT:
        case MIRUO_STATE_TCP_LAST_ACK:
          opt.count_timeout++;
          t = miruo_tcp_session_destroy(t, "destroy session", "time out");
          continue;
      }
    }
    p = t->packet.next;
    /*
    while(p){
      if(p->view){
        // 再送時間の最長を暫定的に30秒として、それ以前に受け取ったパケットを破棄
        // そのため30秒以内の再送は検出できるがそれ以上かかった場合は検知できない
        // 30秒でも十分に大きすぎる気がするのでRTOをどうにか計算したほうがいいかな
        if((opt.now_tv.tv_sec - p->ts.tv_sec) > 30){
        }
      }
    }
    */
    t = t->next;
  }
}

tcpsession *miruo_tcp_syn(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    if(c = add_tcpsession(s)){
      c->packet.color = COLOR_YELLOW;
    }else{
      return(NULL);
    }
  }else{
    if((c->packet.seqno == s->packet.seqno) && 
       (c->packet.ackno == s->packet.ackno)){
      add_tcppacket(c, &(s->packet));
      return(c);
    }else{
      miruo_tcp_session_destroy(c, "error break", "Duplicate connection");
      if(c = add_tcpsession(s)){
        c->packet.color = COLOR_RED;
        c->view = 1;
      }else{
        return(NULL);
      }
    }
  }
  c->st[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->st[1] = MIRUO_STATE_TCP_SYN_RECV;
  c->packet.sno = 0;
  c->packet.rno = 1;
  c->packet.st[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->packet.st[1] = MIRUO_STATE_TCP_SYN_RECV;
  return(c);
}

void miruo_tcp_synack(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    return;
  }
  tcppacket *t = add_tcppacket(c, &(s->packet));
  switch(t->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      t->color = COLOR_YELLOW;
      break;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
      break;
  }
  switch(t->st[1]){
    case MIRUO_STATE_TCP_SYN_SENT:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_EST;
      break;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
      break;
  }
}

void miruo_tcp_ack(tcpsession *c, tcpsession *s)
{
  int f = 0;
  tcppacket *t;
  if(c == NULL){
    return;
  }
  t = add_tcppacket(c, &(s->packet));
  if((t->pno <= opt.showdata) || (opt.verbose > 1)){
    t->view = 0;
  }else{
    t->view = (t->color == 0);
  }
  switch(t->st[0]){
    case MIRUO_STATE_TCP_EST:
      if(t->st[1] == MIRUO_STATE_TCP_FIN_WAIT1){
        t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_CLOSE_WAIT;
        t->view  = 0;
      }
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      if(t->st[1] == MIRUO_STATE_TCP_LAST_ACK){
        t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_TIME_WAIT;
        t->view  = 0;
      }
      break;
  }
  switch(t->st[1]){
    case MIRUO_STATE_TCP_SYN_RECV:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_EST;
      t->color = COLOR_YELLOW;
      t->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_FIN_WAIT2;
      t->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      break;
    case MIRUO_STATE_TCP_LAST_ACK:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_CLOSED;
      t->view  = 0;
      break;
  }
  if((t->st[0] == MIRUO_STATE_TCP_TIME_WAIT) && (t->st[1] == MIRUO_STATE_TCP_CLOSED)){
    t->color = COLOR_BLUE;
  }
}

void miruo_tcp_fin(tcpsession *c, tcpsession *s)
{
  tcppacket *t;
  if(c == NULL){
    return;
  }
  t = add_tcppacket(c, &(s->packet));
  switch(t->st[0]){
    case MIRUO_STATE_TCP_EST:
      t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_LAST_ACK;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
      break;
  }
  switch(t->st[1]){
    case MIRUO_STATE_TCP_EST:
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_TIME_WAIT;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
      break;
  }
}

void miruo_tcp_finack(tcpsession *c, tcpsession *s)
{
  tcppacket *t;
  if(c == NULL){
    return;
  }
  t = add_tcppacket(c, &(s->packet));
  switch(t->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      break;
    case MIRUO_STATE_TCP_EST:
      if(t->st[1] == MIRUO_STATE_TCP_EST){
        t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      }
      if(t->st[1] == MIRUO_STATE_TCP_FIN_WAIT1){
        t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_LAST_ACK;
      }
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_LAST_ACK;
      break;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
  }
  switch(t->st[1]){
    case MIRUO_STATE_TCP_EST:
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_FIN_WAIT2;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      break;
    default:
      c->view  = 1;
      t->view  = 0;
      t->color = COLOR_RED;
  }
}

void miruo_tcp_rst(tcpsession *c, tcpsession *s)
{
  tcppacket *t;
  if(c == NULL){
    return;
  }
  t = add_tcppacket(c, &(s->packet));
  t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_CLOSED;
  t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_CLOSED;
  t->color = COLOR_RED;
  c->view  = (opt.rstmode > 0);
  if((t->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (t->st[1] == MIRUO_STATE_TCP_FIN_WAIT1)){
    c->view = (opt.rstmode > 1);
  }
  if((t->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (t->st[1] == MIRUO_STATE_TCP_FIN_WAIT2)){
    c->view = (opt.rstmode > 1);
  }
}

void miruo_tcp_rstack(tcpsession *c, tcpsession *s)
{
  tcppacket *t;
  if(c == NULL){
    return;
  }
  t = add_tcppacket(c, &(s->packet));
  c->view = (opt.rstmode > 0);
  if((t->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (t->st[1] == MIRUO_STATE_TCP_FIN_WAIT1)){
    c->view = (opt.rstmode > 1);
  }
  if((t->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (t->st[1] == MIRUO_STATE_TCP_FIN_WAIT2)){
    c->view = (opt.rstmode > 1);
  }
  t->st[0] = c->st[t->sno] = MIRUO_STATE_TCP_CLOSED;
  t->st[1] = c->st[t->rno] = MIRUO_STATE_TCP_CLOSED;
  t->color = COLOR_RED;
}

tcpsession *miruo_tcp_flags_switch(tcpsession *c, tcpsession *s)
{
  switch(s->packet.flags & 23){
    case 16:
      miruo_tcp_ack(c, s);
      break;
    case 2:
      c = miruo_tcp_syn(c, s);
      break;
    case 18:
      miruo_tcp_synack(c, s);
      break;
    case 1:
      miruo_tcp_fin(c, s);
      break;
    case 17:
      miruo_tcp_finack(c, s);
      break;
    case 4:
      miruo_tcp_rst(c, s);
      break;
    case 20:
      miruo_tcp_rstack(c, s);
      break;
    default:
      if(c){
        c->view = 1;
        s->packet.view  = 0;
        s->packet.color = COLOR_RED;
        add_tcppacket(c, &(s->packet));
      }
      break;
  }
  return(c);
}

tcpsession *read_tcpsession(tcpsession *c, const struct pcap_pkthdr *ph, const u_char *p)
{
  tcphdr th;
  int l = ph->caplen;
  p = read_header_tcp(&th, (u_char *)p, &l);
  if(p == NULL){
    return(NULL);
  }
  memset(c, 0, sizeof(tcpsession));
  memcpy(&(c->packet.ts), &(ph->ts), sizeof(struct timeval));
  memcpy(&(c->ip[0].sin_addr), &(th.ip.src), sizeof(struct in_addr));
  memcpy(&(c->ip[1].sin_addr), &(th.ip.dst), sizeof(struct in_addr));
  c->ip[0].sin_port = th.sport;
  c->ip[1].sin_port = th.dport;
  c->packet.size    = ph->len;
  c->packet.flags   = th.flags;
  c->packet.seqno   = th.seqno;
  c->packet.ackno   = th.ackno;
  c->packet.optsize = th.offset - 20;
  memcpy(c->packet.opt, th.opt, c->packet.optsize);
  return(c);
}

/************************************************
 *
 * TCPセッションモニタ
 *
 ************************************************/
void miruo_tcp_session(u_char *u, const struct pcap_pkthdr *ph, const u_char *p)
{
  tcpsession *c;
  tcpsession ts;

  if(read_tcpsession(&ts, ph, p) == NULL){
    return;
  }

  c = get_tcpsession(&ts);
  if(tcp_retransmit_process(c, &(ts.packet))){
    return;
  }
  c = miruo_tcp_flags_switch(c, &ts);
  if(is_tcpsession_closed(c)){
    if(opt.verbose > 0){
      c->view = 1;
    }
    if((opt.ct_limit > 0) && (tcp_connection_time(c) > opt.ct_limit)){
      c->view = 1;
    }
    if(c->view){
      opt.count_view++;
    }
    print_tcpsession(stdout, c);
    del_tcpsession(c);
    return;
  }
  if((opt.verbose > 1) && (c != NULL)){
    c->view = 1;
    print_tcpsession(stdout, c);
  }
}

void miruo_finish(int code)
{
  if(opt.p){
    pcap_close(opt.p);
    opt.p = NULL;
  }
  exit(code);
}

struct option *get_optlist()
{
  static struct option opt[4];
  opt[0].name    = "help";
  opt[0].has_arg = 0;
  opt[0].flag    = NULL;
  opt[0].val     = 'h';

  opt[1].name    = "version";
  opt[1].has_arg = 0;
  opt[1].flag    = NULL;
  opt[1].val     = 'V';

  opt[2].name    = "tcp";
  opt[2].has_arg = 1;
  opt[2].flag    = NULL;
  opt[2].val     = 'T';

  opt[3].name    = NULL;
  opt[3].has_arg = 0;
  opt[3].flag    = NULL;
  opt[3].val     = 0;
  return(opt);
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
      opt.alrm = 1;
      break;
  }
}

void miruo_signal()
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

void miruo_timer()
{
  if(setitimer(ITIMER_REAL, &(opt.itv), NULL) == -1){
    fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
    miruo_finish(1);
  }    
}

int miruo_init()
{
  memset(&opt, 0, sizeof(opt));
  opt.loop     = 1;
  opt.alrm     = 1;
  opt.promisc  = 1;
  opt.showdata = 3;
  opt.rsynfind = 1;
  opt.rstmode  = 1;
  opt.stattime = 60;
  opt.pksize   = 96;
  opt.ct_limit = 0;
  opt.rt_limit = 1000;
  opt.ts_limit = 1024;
  opt.tp_limit = 65536;
  opt.color    = isatty(fileno(stdout));
  opt.mode     = MIRUO_MODE_TCP_SESSION;
  opt.itv.it_interval.tv_sec = 1;
  opt.itv.it_value.tv_sec    = 1;
  gettimeofday(&(opt.old_tv), NULL);
  getrusage(RUSAGE_SELF, &(opt.old_rs));
}

void miruo_setopt(int argc, char *argv[])
{
  int   i;
  int   r;
  char *F[8];
  memset(F, 0, sizeof(F));
  F[MIRUO_MODE_TCP_SESSION] = "tcp";
  F[MIRUO_MODE_HTTP]        =  NULL;
  F[MIRUO_MODE_MYSQL]       =  NULL;
  while((r = getopt_long(argc, argv, "hVvR:S:C:D:a:T:t:s:i:m:r:", get_optlist(), NULL)) != -1){
    switch(r){
      case 'h':
        usage();
        miruo_finish(0);
      case 'V':
        version();
        miruo_finish(0);
      case 'v':
        opt.verbose++;
        break;
      case 'R':
        opt.rstmode = atoi(optarg);
        break;
      case 'S':
        opt.rsynfind = atoi(optarg);
        break;
      case 'D':
        opt.showdata = atoi(optarg);
        break;
      case 'C':
        opt.color = atoi(optarg);
        break;
      case 'a':
        if(atoi(optarg) > 0){
          opt.ts_limit = atoi(optarg);
        }
        break;
      case 'T':
        opt.ct_limit = atoi(optarg);
        break;
      case 't':
        opt.rt_limit = atoi(optarg);
        break;
      case 's':
        opt.stattime = atoi(optarg);
        break;
      case 'r':
        strcpy(opt.file, optarg);
        break;
      case 'm':
        if(strcmp("tcp", optarg) == 0){
          opt.mode = MIRUO_MODE_TCP_SESSION;
        }
        break;
      case 'i':
        strcpy(opt.dev, optarg);
        break;
      case '?':
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
  if(F[opt.mode]){
    if(strlen(opt.exp)){
      strcat(opt.exp, " and ");
    }
    strcat(opt.exp, F[opt.mode]);
  }
}

void miruo_pcap()
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
      break;
    default:
      fprintf(stderr, "%s: not support datalink %s(%s)\n", __func__, opt.lkname, opt.lkdesc);
      miruo_finish(1);
  }
}

void miruo_execute_tcp_session_offline()
{
  if(pcap_loop(opt.p, 0, miruo_tcp_session, NULL) == -1){
    fprintf(stderr, "%s: [error] %s\n", __func__, pcap_geterr(opt.p));
  }
  opt.stattime = 1;
  gettimeofday(&(opt.now_tv), NULL);
  getrusage(RUSAGE_SELF, &(opt.now_rs));
  memcpy(&(opt.tm), localtime(&(opt.now_tv.tv_sec)), sizeof(struct tm));
  miruo_tcp_session_statistics(1);
}

void miruo_execute_tcp_session_live(int p)
{
  fd_set fds;
  while(opt.loop){
    FD_ZERO(&fds);
    FD_SET(p,&fds);
    if(opt.alrm){
      opt.alrm = 0;
      gettimeofday(&(opt.now_tv), NULL);
      getrusage(RUSAGE_SELF, &(opt.now_rs));
      memcpy(&(opt.tm), localtime(&(opt.now_tv.tv_sec)), sizeof(struct tm));
      miruo_tcp_session_statistics(0);
      miruo_tcp_session_timeout();
    }
    if(select(1024, &fds, NULL, NULL, NULL) <= 0){
      continue;
    }
    if(FD_ISSET(p, &fds)){
      if(pcap_dispatch(opt.p, 0, miruo_tcp_session, NULL) == -1){
        fprintf(stderr, "%s: [error] %s\n", __func__, pcap_geterr(opt.p));
        break;
      }
    }
  }
  miruo_tcp_session_statistics(1);
}

void miruo_execute_tcp_session()
{
  int p = pcap_fileno(opt.p);
  if(p == 0){
    miruo_execute_tcp_session_offline();
  }else{
    miruo_execute_tcp_session_live(p);
  }
}

void miruo_execute()
{
  printf("listening on %s, link-type %s (%s), capture size %d bytes\n", opt.dev, opt.lkname, opt.lkdesc, opt.pksize);
  switch(opt.mode){
    case MIRUO_MODE_TCP_SESSION:
      miruo_execute_tcp_session();
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
  miruo_signal();
  miruo_timer();
  miruo_pcap();
  miruo_execute();
  miruo_finish(0);
  return(0);
}

