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
  printf("usage: miruo [-m mode] [option] [expression]\n");
  printf("\n");
  printf("  mode\n");
  printf("   tcp          # tcp session check(default)\n");
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
  printf("   -R           # find RST break(tcp only)\n");
  printf("   -RR          # find RST close(tcp only)\n");
  printf("   -t time      # retransmit limit time(Default 1000ms)\n");
  printf("   -s interval  # statistics view interval(Default 60sec)\n");
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
  tcpsession *s;
  tcpsession *t;
  int64_t delay;

  c->sno = 0;
  c->rno = 1;
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
      delay  = c->ts.tv_sec;
      delay -= t->ts.tv_sec;
      delay *= 1000000;
      delay += c->ts.tv_usec;
      delay -= t->ts.tv_usec;
      delay /= 1000;
      delay  = abs(delay);
      if(delay < opt.rt_limit){
        c->sno = 0;
        c->rno = 0;
      }else{
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
  if(tspool.count > 65535){
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
  if(c->last){
    t = c->last;
  }else{
    t = c;
  }
  c->last = new_tcpsession(s);
  t->stok = c->last;
  t->stok->sid   = c->sid;
  t->stok->st[0] = c->cs[s->sno];
  t->stok->st[1] = c->cs[s->rno];
  return(c->last);
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
  opt.total_count++;
}

void print_tcpsession(FILE *fp, tcpsession *s)
{
  struct tm *t;
  char cl[2][16];
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
    sprintf(ts,  "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, s->ts.tv_usec / 1000);
    if(s->color && opt.color){
      sprintf(cl[0], "\x1b[3%dm", s->color);
      sprintf(cl[1], "\x1b[39m");
    }else{
      cl[0][0] = 0;
      cl[1][0] = 0;
    }
    fprintf(fp, "%s[%05d] %s %s %08X/%08X %s %s %s \t%s/%s%s\n",
      cl[0], s->sid, ts, tcp_flag_str(s->flags), s->seqno, s->ackno, nd[0], allow[s->sno], nd[1], st[0], st[1], cl[1]);
    s->view = 1;
  }
  if(s->stok){
    s->stok->views = s->views;
    print_tcpsession(fp, s->stok);
  }
}

void miruo_tcp_session_statistics()
{
  char tstr[32];
  char mstr[64];
  uint64_t size;
  uint32_t   sc;
  tcpsession *t;
  tcpsession *s;
  tcpsession ts;
  static int w = 0;
  if(opt.stattime == 0){
    return;
  }
  if(w){
    w -= opt.interval;
    if(w > 0){
      return;
    }
  }

  w = opt.stattime;
  size = opt.ts_count * sizeof(tcpsession);
  if(size > 1024 * 1024 * 1024){
    sprintf(mstr, "%lluGB", size / 1024 / 1024 / 1024);
  }else if(size > 1024 * 1024){
    sprintf(mstr, "%lluMB", size / 1024 / 1024);
  }else if(size > 1024){
    sprintf(mstr, "%lluKB", size / 1024);
  }else{
    sprintf(mstr, "%lluB", size);
  }

  sprintf(tstr, "%02d:%02d:%02d", opt.tm->tm_hour, opt.tm->tm_min, opt.tm->tm_sec);
  fprintf(stderr, "===== SESSION STATISTICS =====\n");
  fprintf(stderr, "Current Time     : %s\n",   tstr);
  fprintf(stderr, "Total Session    : %llu\n", opt.total_count);
  fprintf(stderr, "View Session     : %llu\n", opt.view_count);
  fprintf(stderr, "Timeout Session  : %llu\n", opt.timeout_count);
  fprintf(stderr, "RST Break Session: %llu\n", opt.rstbreak_count);
  fprintf(stderr, "ActiveSession    : %u\n",   opt.ac_count);
  fprintf(stderr, "SessionPool(use) : %u\n",   opt.ts_count - tspool.count);
  fprintf(stderr, "SessionPool(free): %u\n",   tspool.count);
  fprintf(stderr, "Use memmory size : %s\n",   mstr);
  fprintf(stderr, "----- Error Count Report -----\n");
  fprintf(stderr, "L2 : %d\n", opt.L2err);
  fprintf(stderr, "IP : %d\n", opt.IPerr);
  fprintf(stderr, "TCP: %d\n", opt.TCPerr);
  if(tsact[0]){
    fprintf(stderr, "----- ACTIVE SESSIONLIST -----\n");
  }
  for(t=tsact[0];t;t=t->next){
    sc = 1;
    for(s=t->stok;s;s=s->stok){
      sc++;
    }
    memcpy(&ts, t, sizeof(tcpsession));
    ts.view  = 0;
    ts.views = 1;
    ts.color = 0;
    ts.stok  = NULL;
    ts.prev  = NULL;
    ts.next  = NULL;
    ts.st[0] = ts.cs[0];
    ts.st[1] = ts.cs[1];
    fprintf(stderr, "%05d: ", sc);
    print_tcpsession(stderr, &ts);
  }
  fprintf(stderr, "==============================\n");
}

tcpsession *miruo_tcp_session_destroy(tcpsession *t, char *msg)
{
  t->views = 1;
  opt.view_count++;
  print_tcpsession(stdout, t);
  fprintf(stdout, msg);
  return(del_tcpsession(t));
}

void miruo_tcp_session_timeout()
{
  char ts[32];
  char sc[2][8];
  char msg[256];
  tcpsession *t;
  tcpsession *s;
  tcpsession *r;

  t = tsact[0];
  if(t == NULL){
    return;
  }
  sprintf(ts, "%02d:%02d:%02d.%03u", opt.tm->tm_hour, opt.tm->tm_min, opt.tm->tm_sec, opt.tv.tv_usec/1000);
  if(opt.color){
    sprintf(sc[0], "\x1b[31m");
    sprintf(sc[1], "\x1b[39m");
  }else{
    sc[0][0] = 0;
    sc[1][1] = 0;
  }
  while(t){
    if((opt.tv.tv_sec - t->ts.tv_sec) > 30){
      if(t->cs[0] == MIRUO_STATE_TCP_SYN_SENT){
        opt.timeout_count++;
        sprintf(msg, "%s[%05d] %s destroy session (time out)%s\n", sc[0], t->sid, ts, sc[1]);
        t = miruo_tcp_session_destroy(t, msg);
        continue;
      }
      if(t->cs[0] == MIRUO_STATE_TCP_SYN_RECV){
        opt.timeout_count++;
        sprintf(msg, "%s[%05d] %s destroy session (time out)%s\n", sc[0], t->sid, ts, sc[1]);
        t = miruo_tcp_session_destroy(t, msg);
        continue;
      }
    }
    r = t;
    s = t->stok;
    while(s){
      if(s->view){
        // 再送時間の最大値を暫定的に30秒とする
        // 30秒以内の再送は検出できるがそれ以上かかった場合は検知できない
        // 30秒でも十分に大きすぎる気がするのでRTOをどうにか計算したほうがいいかな
        if((opt.tv.tv_sec - s->ts.tv_sec) > 30){
          r->stok = s->stok;
          s->stok = NULL;
          if(t->last == s){
            t->last = r;
          }
          free_tcpsession(s);
          s = r->stok;
          continue;
        }
      }
      r = s;
      s = s->stok;
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
  s = stok_tcpsession(c, s);
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
  uint32_t    l;
  tcpsession  s;
  tcpsession *c;

  l = h->caplen;
  q = (u_char *)p;
  q = read_l2hdr(&l2, q, &l);
  if(q == NULL){
    opt.L2err++;
    return; // 不正なフレームは破棄
  }
  if(get_l3type(&l2) != 0x0800){
    return; // IP以外は破棄
  }

  q = iphdr_read(&ih, q, &l);
  if(q == NULL){
    opt.IPerr++;
    return; // 不正なIPヘッダ
  }
  if(ih.offset != 0){
    return; // フラグメントの先頭以外は破棄
  }
  if(ih.Protocol != 6){
    return; // TCP以外は破棄
  }

  q = tcphdr_read(&th, q, &l);
  if(q == NULL){
    opt.TCPerr++;
    return; // 不正なTCPヘッダ
  }

  hdr2tcpsession(&s, &ih, &th, &(h->ts));
  c = get_tcpsession(&s);
  if(s.sno == s.rno){
    return;
  }

  switch(th.flags & 23){
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
      c->views = 1;
      s.view   = 0;
      s.color  = COLOR_RED;
      stok_tcpsession(c, &s);
      break;
  }
  if(is_tcpsession_closed(c)){
    if(opt.verbose > 0){
      c->views = 1;
    }
    if(c->views){
      opt.view_count++;
    }
    print_tcpsession(stdout, c);
    del_tcpsession(c);
  }else{
    if((opt.verbose > 1) && (c != NULL)){
      c->views = 1;
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
  //pcap_breakloop(opt.p);
}

void signal_term_handler()
{
  opt.loop = 0;
  //pcap_breakloop(opt.p);
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
  struct itimerval itv;
  memset(&itv, 0, sizeof(itv));
  itv.it_interval.tv_sec = opt.interval;
  itv.it_value.tv_sec    = opt.interval;
  if(setitimer(ITIMER_REAL, &itv, NULL) == -1){
    fprintf(stderr, "%s: %s\n", __func__, strerror(errno));
    miruo_finish(1);
  }    
}

int miruo_init()
{
  memset(&opt,    0, sizeof(opt));
  memset(tsact,   0, sizeof(tsact));
  memset(&tspool, 0, sizeof(tspool));
  opt.loop     = 1;
  opt.interval = 1;
  opt.promisc  = 1;
  opt.setalrm  = 1;
  opt.stattime = 60;
  opt.pksize   = 96;
  opt.rt_limit = 1000;
  opt.color    = isatty(fileno(stdout));
  opt.mode     = MIRUO_MODE_TCP_SESSION;
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
  while((r = getopt_long(argc, argv, "hVvRC:t:s:i:m:r:", get_optlist(), NULL)) != -1){
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
        opt.rstclose++;
        break;
      case 'C':
        opt.color = atoi(optarg);
        break;
      case 't':
        if(atoi(optarg) > 0){
          opt.rt_limit = atoi(optarg);
        }
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
    case 1:
    case 113:
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
  opt.setalrm  = 1;
  opt.stattime = 1;
  gettimeofday(&(opt.tv), NULL);
  opt.tm = localtime(&(opt.tv.tv_sec));
  miruo_tcp_session_statistics();
  return;
}

void miruo_execute_tcp_session_live(int p)
{
  fd_set fds;
  while(opt.loop){
    FD_ZERO(&fds);
    FD_SET(p,&fds);
    if(opt.setalrm){
      opt.setalrm = 0;
      gettimeofday(&(opt.tv), NULL);
      opt.tm = localtime(&(opt.tv.tv_sec));
      miruo_tcp_session_statistics();
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

