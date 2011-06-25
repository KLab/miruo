#include "miruo.h"

miruopt opt;
tcpsession *tsact[256];
tcpsession_pool tspool;

void version()
{
  printf("miruo version 0.7\n");
}

void usage()
{
  version();
  printf("usage: miruo -m mode [option] [expression]\n");
  printf("\n");
  printf("  mode\n");
  printf("   tcp          # tcp session check\n");
  printf("   http         # http request monitor(not yet)\n");
  printf("   mysql        # mysql query  monitor(not yet)\n");
  printf("\n");
  printf("  option\n");
  printf("   -h           # help\n");
  printf("   -V           # version\n");
  printf("   -v           # verbose\n");
  printf("   -vv          # more verbose\n");
  printf("   -vvv         # most verbose\n");
  printf("   -C0          # color off\n");
  printf("   -C1          # color on\n");
  printf("   -R           # find RST break\n");
  printf("   -RR          # find RST close\n");
  printf("   -Stime       # status view\n");
  printf("   -r file      # read file(for tcpdump -w)\n");
  printf("   -i interface # \n");
  printf("\n");
  printf("  expression: see man tcpdump\n");
  printf("\n");
  printf("  ex)\n");
  printf("    miruo -m tcp host 192.168.0.100 and port 80\n");
  printf("    miruo -m tcp src host 192.168.0.1\n");
}

void dump_data(uint8_t *data, int size)
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

void print_mac(char *mac)
{
  int i=0;
  printf("%02X",mac[i]);
  for(i=1;i<6;i++){
    printf(":%02X",mac[i]);
  }
}

void print_iphdr(iphdr *h)
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
  printf("Checksum: %hu\n",  h->Checksum);
  printf("SrcAddr : %s\n",   inet_ntoa(h->src));
  printf("DstAddr : %s\n",   inet_ntoa(h->dst));
  for(i=5;i<h->IHL;i++){
    printf("Options[%d]: 0x%04x\n", i - 5, h->options[i - 5]);
  }
}

char *get_state_string(int state)
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

void print_tcphdr(tcphdr *h)
{
  char *flags = tcp_flag_str(h->flags);
  printf("======= TCP HEADER =======\n");
  printf("sport   : %hu\n",     h->sport);
  printf("dport   : %hu\n",     h->dport);
  printf("seqno   : %u\n",      h->seqno);
  printf("ackno   : %u\n",      h->ackno);
  printf("offset  : %hhu\n",    h->offset);
  printf("flags   : %s\n",      flags);
  printf("window  : %hd\n",     h->window);
  printf("checksum: 0x%04hx\n", h->checksum);
}

u_char *read_ethhdr(ethhdr *h, u_char *p, uint32_t *l)
{
  if(*l <= 14){
    return(NULL);
  }
  memcpy(h->smac, p, sizeof(h->smac));
  p  += 6;
  *l -= 6;
  memcpy(h->dmac, p, sizeof(h->dmac));
  p  += 6;
  *l -= 6;
  h->type = ntohs((uint16_t)*p);
  p  += 2;
  *l -= 2;
  return(p);
}

u_char *read_sllhdr(sllhdr *h, u_char *p, uint32_t *l)
{
  if(*l <= 16){
    return(NULL);
  }
  p  += 14;
  *l -= 14;
  h->type = ntohs(*((uint16_t *)p));
  p  += 2;
  *l -= 2;
  return(p);
}

uint8_t *read_l2hdr(l2hdr *hdr, u_char *p, uint32_t *l){
  switch(opt.lktype){
    case 1:
      return read_ethhdr(&(hdr->hdr.eth), p, l);
    case 113:
      return read_sllhdr(&(hdr->hdr.sll), p, l);
  }
  return(NULL);
}


u_char *iphdr_read(iphdr *h, u_char *p, int *l)
{
  int i;
  uint32_t d;

  if(*l < 4){
    return(NULL);
  }
  d = ntohl(*((uint32_t *)p));
  h->Ver = (d >> 28) & 0x000f;
  h->IHL = (d >> 24) & 0x000f;
  h->TOS = (d >> 16) & 0x00ff;
  h->len = (d >>  0) & 0xffff;
  p  += 4;
  *l -= 4;

  if(*l < 4){
    return(NULL);
  }
  d = ntohl(*((uint32_t *)p));
  h->id     = (d >> 16) & 0xffff;
  h->flags  = (d >> 13) & 0x0007;
  h->offset = (d >>  0) & 0x1fff;
  p  += 4;
  *l -= 4;

  if(*l < 4){
    return(NULL);
  }
  d = ntohl(*((uint32_t *)p));
  h->TTL      = (d >> 24) & 0x00ff;
  h->Protocol = (d >> 16) & 0x00ff;
  h->Checksum = (d >>  0) & 0xffff;
  p  += 4;
  *l -= 4;

  if(*l < 4){
    return(NULL);
  }
  d = ntohl(*((uint32_t *)p));
  h->src.s_addr = ntohl(d);
  p  += 4;
  *l -= 4;

  if(*l < 4){
    return(NULL);
  }
  d = ntohl(*((uint32_t *)p));
  h->dst.s_addr = ntohl(d);
  p  += 4;
  *l -= 4;

  for(i=5;i<h->IHL;i++){
    if(*l < 4){
      return(NULL);
    }
    h->options[i-5] = ntohl(*((uint32_t *)p));
    p  += 4;
    *l -= 4;
  }
  return(p);
}

u_char *tcphdr_read(tcphdr *h, u_char *p, int *l)
{
  if(*l < 20){
    fprintf(stderr, "%s: len=%d need=20\n", __func__, *l);
    return(NULL);
  }
  memcpy(h, p, sizeof(tcphdr));
  h->sport    = ntohs(h->sport); 
  h->dport    = ntohs(h->dport); 
  h->seqno    = ntohl(h->seqno); 
  h->ackno    = ntohl(h->ackno); 
  h->offset   = h->offset >> 2;
  h->window   = ntohl(h->window);
  h->checksum = ntohl(h->checksum);
  h->urgent   = ntohl(h->urgent);
  if(*l < h->offset){
    return(NULL);
  }
  p  += h->offset;
  *l -= h->offset;
  return(p);
}

int is_tcpsession_closed(tcpsession *c){
  if(c == NULL){
    return(0);
  }
  if((c->cs[0] == MIRUO_STATE_TCP_CLOSED) && (c->cs[1] == MIRUO_STATE_TCP_CLOSED)){
    return(1);
  }
  if((c->cs[0] == MIRUO_STATE_TCP_TIME_WAIT) && (c->cs[1] == MIRUO_STATE_TCP_CLOSED)){
    return(1);
  }
  if((c->cs[0] == MIRUO_STATE_TCP_CLOSED) && (c->cs[1] == MIRUO_STATE_TCP_TIME_WAIT)){
    return(1);
  }
  return(0);
}

tcpsession *get_tcpsession(tcpsession *c)
{
  double  delay;
  tcpsession *s;
  tcpsession *t;
  for(s=tsact[0];s;s=s->next){
    if((memcmp(&(c->src), &(s->src), sizeof(c->src)) == 0) && (memcmp(&(c->dst), &(s->dst), sizeof(c->dst)) == 0)){
      c->sno = 0;
      c->rno = 1;
      break;
    }
    if((memcmp(&(c->src), &(s->dst), sizeof(c->src)) == 0) && (memcmp(&(c->dst), &(s->src), sizeof(c->dst)) == 0)){
      c->sno = 1;
      c->rno = 0;
      break;
    }
  }
  for(t=s;t;t=t->stok){
    if((t->seqno == c->seqno) && (t->ackno == c->ackno) && (t->flags == c->flags)){
      delay  = c->ts.tv_usec;
      delay /= 1000000;
      delay += c->ts.tv_sec;
      delay -= t->ts.tv_sec;
      delay -= ((double)t->ts.tv_usec / 1000000.0);
      delay *= 1000;
      delay  = fabs(delay);
      // 1msec以下の再送は許容する
      if(delay > 1){
        s->views = 1;
        t->view  = 0;
        c->view  = 0;
        t->color = COLOR_GREEN;
        c->color = COLOR_RED;
      }
      break;
    }  
  } 
  return(s);
}

tcpsession *malloc_tcpsession()
{
  tcpsession *s;
  if(s = tspool.free){
    if(tspool.free = s->next){
      s->next->prev = NULL;
      s->next = NULL;
    }
    tspool.count--;
  }else{
    if(s = malloc(sizeof(tcpsession))){
      opt.ts_count++;
    }
  }
  return(s);
}

void free_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  tcpsession *s = c->stok;
  if(tspool.count > 8192){
    free(c);
    opt.ts_count--;
  }else{
    if(c->next = tspool.free){
      c->next->prev = c;
    }
    tspool.free = c;
    tspool.count++;
  }
  free_tcpsession(s);
}

tcpsession *new_tcpsession(tcpsession *c)
{
  static uint16_t sid = 0;
  tcpsession *s = malloc_tcpsession();
  if(c){
    memcpy(s, c, sizeof(tcpsession));
  }else{
    memset(s, 0, sizeof(tcpsession));
  }
  s->sid = sid++;
  return(s);
}

tcpsession *del_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  tcpsession *p = c->prev; 
  tcpsession *n = c->next;
  if(c == tsact[0]){
    if(tsact[0] = n){
      tsact[0]->prev = NULL;
    }
  }else{
    if(p){
      p->next = n;
    }
    if(n){
      n->prev = p;
    }
  }
  opt.ac_count--;
  free_tcpsession(c);
  return(n);
}

tcpsession *stok_tcpsession(tcpsession *c, tcpsession *s)
{
  tcpsession *t;
  if(c == NULL){
    return;
  }
  for(t=c;t->stok;t=t->stok);
  t->stok = new_tcpsession(s);
  t->stok->sid   = c->sid;
  t->stok->st[0] = c->cs[s->sno];
  t->stok->st[1] = c->cs[s->rno];
  return(t->stok);
}

void add_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  while(c->next){
    c = c->next;
  }
  if(c->next = tsact[0]){
    c->next->prev = c;
  }
  tsact[0] = c;
  opt.ac_count++;
}

void print_tcpsession(tcpsession *s)
{
  struct tm *t;
  char nd[2][64];
  char st[2][64];
  char ts[256];
  char *allow[] = {"->", "<-"};
  if(s == NULL){
    return;
  }
  if(s->views == 0){
    return;
  }
  if(s->view == 0){
    t = localtime(&(s->ts.tv_sec));
    sprintf(nd[s->sno], "%s:%u", inet_ntoa(s->src.in.sin_addr), s->src.in.sin_port);
    sprintf(nd[s->rno], "%s:%u", inet_ntoa(s->dst.in.sin_addr), s->dst.in.sin_port);
    sprintf(st[0], "%s", get_state_string(s->st[s->sno]));
    sprintf(st[1], "%s", get_state_string(s->st[s->rno]));
    sprintf(ts,  "%02d:%02d:%02d.%06u", t->tm_hour, t->tm_min, t->tm_sec, s->ts.tv_usec);
    if(s->color && opt.color){
      printf("\x1b[3%dm", s->color);
    }
    printf("[%05d] %s %s %08X/%08X %s %s %s \t%s/%s\n",
      s->sid, ts, tcp_flag_str(s->flags), s->seqno, s->ackno, nd[0], allow[s->sno], nd[1], st[0], st[1]);
    if(s->color && opt.color){
      printf("\x1b[39m");
    }
    s->view = 1;
  }
  if(s->stok){
    s->stok->views = s->views;
    print_tcpsession(s->stok);
  }
}

void miruo_tcp_session_status()
{
  tcpsession *t;
  tcpsession ts;
  if(opt.setalrm == 0){
    return;
  }
  if(opt.statuson == 0){
    return;
  }
  printf("===== TCP SESSION STATUS =====\n");
  printf("ActiveSession    : %d\n", opt.ac_count);
  printf("SessionPool(use) : %d\n", opt.ts_count - tspool.count);
  printf("SessionPool(free): %d\n", tspool.count);
  if(tsact[0]){
    printf("===== ACTIVE SESSIONLIST =====\n");
  }
  for(t=tsact[0];t;t=t->next){
    memcpy(&ts, t, sizeof(tcpsession));
    ts.view  = 0;
    ts.views = 1;
    ts.color = 0;
    ts.stok  = NULL;
    ts.prev  = NULL;
    ts.next  = NULL;
    ts.st[0] = ts.cs[0];
    ts.st[1] = ts.cs[1];
    print_tcpsession(&ts);
  }
  printf("==============================\n");
}

tcpsession *miruo_tcp_session_destroy(tcpsession *t, char *msg)
{
  t->views = 1;
  print_tcpsession(t);
  printf(msg);
  return(del_tcpsession(t));
}

void miruo_tcp_session_timeout()
{
  char ts[32];
  char sc[2][8];
  char msg[256];
  struct tm *lt;
  tcpsession *t;
  struct timeval tv;
  if(opt.setalrm == 0){
    return;
  }
  t = tsact[0];
  if(t == NULL){
    return;
  }
  gettimeofday(&tv, NULL);
  lt = localtime(&(tv.tv_sec));
  sprintf(ts, "%02d:%02d:%02d.%03u", lt->tm_hour, lt->tm_min, lt->tm_sec, tv.tv_usec/1000);
  if(opt.color){
    sprintf(sc[0], "\x1b[31m");
    sprintf(sc[1], "\x1b[39m");
  }else{
    sc[0][0] = 0;
    sc[1][1] = 0;
  }
  while(t){
    if((tv.tv_sec - t->ts.tv_sec) > 30){
      if(t->cs[0] == MIRUO_STATE_TCP_SYN_SENT){
        sprintf(msg, "%s[%05d] %s destroy session (time out)%s\n", sc[0], t->sid, ts, sc[1]);
        t = miruo_tcp_session_destroy(t, msg);
        continue;
      }
      if(t->cs[0] == MIRUO_STATE_TCP_SYN_RECV){
        sprintf(msg, "%s[%05d] %s destroy session (time out)%s\n", sc[0], t->sid, ts, sc[1]);
        t = miruo_tcp_session_destroy(t, msg);
        continue;
      }
    }
    t = t->next;
  }
}


void miruo_tcp_syn(tcpsession *c, tcpsession *s)
{
  if(c){
    s = stok_tcpsession(c, s);
    return;
  }
  c = new_tcpsession(s);
  c->sno = 0;
  c->rno = 1;
  c->color = COLOR_YELLOW;
  c->st[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->st[1] = MIRUO_STATE_TCP_LISTEN;
  c->cs[0] = MIRUO_STATE_TCP_SYN_SENT;
  c->cs[1] = MIRUO_STATE_TCP_LISTEN;
  add_tcpsession(c);
}

void miruo_tcp_synack(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    c = new_tcpsession(s);
    c->sno = 0;
    c->rno = 1;
    c->views = 1;
    c->color = COLOR_RED;
    c->st[0] = MIRUO_STATE_TCP_SYN_RECV;
    c->st[1] = MIRUO_STATE_TCP_SYN_SENT;
    c->cs[0] = MIRUO_STATE_TCP_SYN_RECV;
    c->cs[1] = MIRUO_STATE_TCP_SYN_SENT;
    add_tcpsession(c);
    return;
  }
  s->st[0] = c->cs[s->sno];
  s->st[1] = c->cs[s->rno];
  switch(s->st[0]){
    case MIRUO_STATE_TCP_LISTEN:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_SYN_RECV;
      break;
    default:
      c->views = 1;
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_SYN_SENT:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_EST;
      break;
    default:
      c->views = 1;
      s->view  = 0;
      s->color = COLOR_RED;
      break;
  }
  stok_tcpsession(c, s);
}

void miruo_tcp_ack(tcpsession *c, tcpsession *s)
{
  int f = 0;
  if(c == NULL){
    return;
  }
  s = stok_tcpsession(c, s);
  s->view = (opt.verbose < 2) && (s->color == 0);
  switch(s->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_EST;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_TIME_WAIT;
      s->view  = 0;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_SYN_RECV:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_EST;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_FIN_WAIT2;
      s->view  = 0;
      break;
    case MIRUO_STATE_TCP_LAST_ACK:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_CLOSED;
      s->view  = 0;
      break;
  }
  if((s->st[0] == MIRUO_STATE_TCP_TIME_WAIT) && (s->st[1] == MIRUO_STATE_TCP_CLOSED)){
    s->color = COLOR_BLUE;
  }
}

void miruo_tcp_fin(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    return;
  }
  s = stok_tcpsession(c, s);
  switch(s->st[0]){
    case MIRUO_STATE_TCP_EST:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_LAST_ACK;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_EST:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_CLOSE_WAIT;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT2:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_TIME_WAIT;
      break;
  }
}

void miruo_tcp_finack(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    return;
  }
  s = stok_tcpsession(c, s);
  switch(s->st[0]){
    case MIRUO_STATE_TCP_SYN_RECV:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      break;
    case MIRUO_STATE_TCP_EST:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_FIN_WAIT1;
      break;
    case MIRUO_STATE_TCP_CLOSE_WAIT:
      s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_LAST_ACK;
      break;
  }
  switch(s->st[1]){
    case MIRUO_STATE_TCP_EST:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_CLOSE_WAIT;
      break;
    case MIRUO_STATE_TCP_FIN_WAIT1:
      s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_FIN_WAIT2;
      break;
  }
}

void miruo_tcp_rst(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    return;
  }
  s = stok_tcpsession(c, s);
  s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_CLOSED;
  s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_CLOSED;
  s->color = COLOR_RED;
  c->views = (opt.rstclose > 0);
  if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT1)){
    c->views = (opt.rstclose > 1);
  }
  if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT2)){
    c->views = (opt.rstclose > 1);
  }
}

void miruo_tcp_rstack(tcpsession *c, tcpsession *s)
{
  if(c == NULL){
    return;
  }
  s = stok_tcpsession(c, s);
  c->views = (opt.rstclose > 0);
  if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT1)){
    c->views = (opt.rstclose > 1);
  }
  if((s->st[0] == MIRUO_STATE_TCP_CLOSE_WAIT) && (s->st[1] == MIRUO_STATE_TCP_FIN_WAIT2)){
    c->views = (opt.rstclose > 1);
  }
  s->st[0] = c->cs[s->sno] = MIRUO_STATE_TCP_CLOSED;
  s->st[1] = c->cs[s->rno] = MIRUO_STATE_TCP_CLOSED;
  s->color = COLOR_RED;
}

void hdr2tcpsession(tcpsession *s, iphdr *ih, tcphdr *th, const struct timeval *ts)
{
  memset(s, 0, sizeof(tcpsession));
  memcpy(&(s->ts), ts, sizeof(struct timeval));
  memcpy(&(s->src.in.sin_addr), &(ih->src), sizeof(struct in_addr));
  memcpy(&(s->dst.in.sin_addr), &(ih->dst), sizeof(struct in_addr));
  s->src.in.sin_port = th->sport;
  s->dst.in.sin_port = th->dport;
  s->flags = th->flags;
  s->seqno = th->seqno;
  s->ackno = th->ackno;
}

uint16_t get_l3type(l2hdr *hdr)
{
  switch(opt.lktype){
    case 1:
      return(hdr->hdr.eth.type);
    case 113:
      return(hdr->hdr.sll.type);
  }
  return(0);
}

/***********************************************
 *
 * TCPセッションチェックの本体
 *
************************************************/
void miruo_tcp_session(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
  l2hdr      l2;
  iphdr      ih;
  tcphdr     th;
  u_char     *q;
  uint8_t     r;
  uint32_t    l;
  uint32_t    v;
  tcpsession  s;
  tcpsession *c;

  v = 0;
  l = h->caplen;
  q = (u_char *)p;

  q = read_l2hdr(&l2, q, &l);
  if(q == NULL){
    fprintf(stderr, "%s: not support datalink %s\n", __func__, opt.lkdesc);
    pcap_breakloop(opt.p);
    return;
  }

  if(get_l3type(&l2) != 0x0800){
    fprintf(stderr, "%s: not support protocol %04x\n", __func__, get_l3type(&l2));
    pcap_breakloop(opt.p);
    return;
  }

  q = iphdr_read(&ih, q, &l);
  if(q == NULL){
    fprintf(stderr, "%s: IP header read error\n", __func__);
    pcap_breakloop(opt.p);
    return;
  }
  if(ih.offset != 0){
    return; /* フラグメントの先頭以外は破棄 */
  }
  if(ih.Protocol != 6){
    fprintf(stderr, "%s: not TCP protocol=%d\n", __func__, ih.Protocol);
    pcap_breakloop(opt.p);
    return; /* TCP以外は破棄 */
  }

  q = tcphdr_read(&th, q, &l);
  if(q == NULL){
    fprintf(stderr, "error: TCP Head Read error\n");
    return;
  }

  hdr2tcpsession(&s, &ih, &th, &(h->ts));
  th.flags &= 23; /* FIN/SYN/ACK/RST以外はリセット */
  c = get_tcpsession(&s);

  switch(th.flags){
    case 2:
      miruo_tcp_syn(c, &s);
      break;
    case 16:
      miruo_tcp_ack(c, &s);
      break;
    case 18:
      miruo_tcp_synack(c, &s);
      break;
    case 1:
      miruo_tcp_fin(c, &s);
      break;
    case 17:
      miruo_tcp_finack(c, &s);
      break;
    case 4:
      miruo_tcp_rst(c, &s);
      break;
    case 20:
      miruo_tcp_rstack(c, &s);
      break;
    default:
      printf("flags=%d\n", th.flags);
      stok_tcpsession(c, &s);
      break;
  }
  if(is_tcpsession_closed(c)){
    if(opt.verbose > 0){
      c->views = 1;
    }
    print_tcpsession(c);
    del_tcpsession(c);
  }
  miruo_tcp_session_status();
  miruo_tcp_session_timeout();
  opt.setalrm = 0; 
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
  pcap_breakloop(opt.p);
}

void signal_term_handler()
{
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
      opt.setalrm = 1;
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
    exit(1);
  }
  if(sigaction(SIGTERM, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGTERM\n", __func__);
    exit(1);
  }
  if(sigaction(SIGPIPE, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGPIPE\n", __func__);
    exit(1);
  }
  if(sigaction(SIGUSR1, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGUSR1\n", __func__);
    exit(1);
  }
  if(sigaction(SIGUSR2, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGUSR2\n", __func__);
    exit(1);
  }
  if(sigaction(SIGALRM, &sig, NULL) == -1){
    fprintf(stderr, "%s: sigaction error SIGALRM\n", __func__);
    exit(1);
  }
}

int miruo_init()
{
  char *p;
  char  e[PCAP_ERRBUF_SIZE];
  memset(&opt,    0, sizeof(opt));
  memset(tsact,   0, sizeof(tsact));
  memset(&tspool, 0, sizeof(tspool));
  p = pcap_lookupdev(e);
  if(p == NULL){
    fprintf(stderr,"%s: %s\n", __func__, e);
  }else{
    strcpy(opt.dev, p);
  }
  miruo_signal();
  opt.pksize   = 96;
  opt.promisc  = 1;
  opt.interval = 10;
  opt.color    = isatty(fileno(stdout));
}

int miruo_set_timer(int interval)
{
  struct itimerval itv;
  itv.it_interval.tv_sec  = interval;
  itv.it_interval.tv_usec = 0;
  itv.it_value.tv_sec     = interval;
  itv.it_value.tv_usec    = 0;
  return(setitimer(ITIMER_REAL, &itv, NULL));
}

int main(int argc, char *argv[])
{
  int i;
  int r;
  int m;
  const char *p;
  char filter[64];
  char errmsg[PCAP_ERRBUF_SIZE];
  struct bpf_program pf;
  pcap_handler hn = NULL;

  miruo_init();
  memset(filter, 0, sizeof(filter));
  memset(errmsg, 0, sizeof(errmsg));
  while((r = getopt_long(argc, argv, "hVvRC:S::i:m:r:", get_optlist(), NULL)) != -1){
    switch(r){
      case 'h':
        usage();
        exit(0);
      case 'V':
        version();
        exit(0);
      case 'v':
        opt.verbose++;
        break;
      case 'R':
        opt.rstclose++;
        break;
      case 'C':
        opt.color = atoi(optarg);
        break;
      case 'S':
        opt.statuson = 1;
        if(optarg){
          opt.interval = atoi(optarg);
        }
        break;
      case 'r':
        strcpy(opt.file, optarg);
        break;
      case 'm':
        if(strcmp("tcp", optarg) == 0){
          m = MIRUO_MODE_TCP_SESSION;
          hn = miruo_tcp_session;
          strcpy(filter, "tcp");
        }
        break;
      case 'i':
        strcpy(opt.dev, optarg);
        break;
      case '?':
        usage();
        exit(1);
    }
  }
  if(hn == NULL){
    usage(0);
    exit(1);
  }
  for(i=optind;i<argc;i++){
    if(strlen(opt.exp)){
      strcat(opt.exp, " ");
    }
    strcat(opt.exp, argv[i]);
  }
  if(strlen(filter)){
    if(strlen(opt.exp)){
      strcat(opt.exp, " and ");
    }
    strcat(opt.exp, filter);
  }

  opt.p = pcap_open_live(opt.dev, opt.pksize, opt.promisc, 1000, errmsg);

  if(opt.p == NULL){
    fprintf(stderr, "pcap_open_live error: %s %s\n", errmsg, opt.dev);
    return(1);
  }

  if(pcap_compile(opt.p, &pf, opt.exp, 0, 0)){
    fprintf(stderr, "pcap_compile error: %s '%s'\n", pcap_geterr(opt.p), opt.exp);
    return(1);
  }

  if(pcap_setfilter(opt.p, &pf)){
    fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(opt.p));
    return(1);
  }

  opt.pksize = pcap_snapshot(opt.p);
  opt.lktype = pcap_datalink(opt.p);
  if(p = pcap_datalink_val_to_name(opt.lktype)){
    strcpy(opt.lkname, p);
  }
  if(p = pcap_datalink_val_to_description(opt.lktype)){
    strcpy(opt.lkdesc, p);
  }

  if(miruo_set_timer(opt.interval) == -1){
    fprintf(stderr, "%s: timer error %s\n", __func__, strerror(errno));
  }

  printf("listening on %s, link-type %s (%s), capture size %d bytes\n", opt.dev, opt.lkname, opt.lkdesc, opt.pksize);
  if(pcap_loop(opt.p, -1, hn, NULL) == -1){
    fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(opt.p));
  }

  pcap_close(opt.p);
  opt.p = NULL;
  return(0);
}

