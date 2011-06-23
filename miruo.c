#include "miruo.h"

IPdata  *IPTOP  = NULL;
TCPdata *TCPTOP = NULL;
L7data  *L7TOP  = NULL;

miruopt opt;
tcpsession *actsession[256];
tcpsession *tcpsession_free;

void version()
{
  printf("miruo version 0.5\n");
}

void usage()
{
  version();
  printf("usage: miruo [-T] [option] [expression]\n");
  printf("\n");
  printf("  option\n");
  printf("   -h           # help\n");
  printf("   -V           # version\n");
  printf("   -v           # verbose\n");
  printf("   -i interface # \n");
  printf("   -T           # tcp session monitor\n");
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

u_char *ethhdr_read(ethhdr *h, u_char *p)
{
  memcpy(h->smac, p, sizeof(h->smac));
  p += 6;
  memcpy(h->dmac, p, sizeof(h->dmac));
  p += 6;
  h->type = ntohs((uint16_t)*p);
  p += 2;
  return(p);
}

u_char *iphdr_read(iphdr *h, u_char *p)
{
  int i;
  uint32_t d;

  d = ntohl(*((uint32_t *)p));
  h->Ver = (d >> 28) & 0x000f;
  h->IHL = (d >> 24) & 0x000f;
  h->TOS = (d >> 16) & 0x00ff;
  h->len = (d >>  0) & 0xffff;
  p += 4;

  d = ntohl(*((uint32_t *)p));
  h->id     = (d >> 16) & 0xffff;
  h->flags  = (d >> 13) & 0x0007;
  h->offset = (d >>  0) & 0x1fff;
  p += 4;

  d = ntohl(*((uint32_t *)p));
  h->TTL      = (d >> 24) & 0x00ff;
  h->Protocol = (d >> 16) & 0x00ff;
  h->Checksum = (d >>  0) & 0xffff;
  p += 4;

  d = ntohl(*((uint32_t *)p));
  h->src.s_addr = ntohl(d);
  p += 4;

  d = ntohl(*((uint32_t *)p));
  h->dst.s_addr = ntohl(d);
  p += 4;

  for(i=5;i<h->IHL;i++){
    h->options[i-5] = ntohl(*((uint32_t *)p));
    p += 4;
  }
  return(p);
}

u_char *tcphdr_read(tcphdr *h, u_char *p)
{
  memcpy(h, p, sizeof(tcphdr));
  h->sport    = ntohs(h->sport); 
  h->dport    = ntohs(h->dport); 
  h->seqno    = ntohl(h->seqno); 
  h->ackno    = ntohl(h->ackno); 
  h->offset   = h->offset >> 2;
  h->window   = ntohl(h->window);
  h->checksum = ntohl(h->checksum);
  h->urgent   = ntohl(h->urgent);
  return(p + h->offset);
}

void miruo(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
  ethhdr  eh;
  iphdr   ih;
  tcphdr  th;
  u_char  *q;
  u_char  *t;
  int tcplen;

  q = ethhdr_read(&eh, (u_char *)p);
  q = iphdr_read(&ih, q);
  t = tcphdr_read(&th, q);
  tcplen = h->len - (t - p);
  if(th.flags & 2){
    print_iphdr(&ih);
    print_tcphdr(&th);
  }
}

tcpsession *get_tcpsession(tcpsession *c)
{
  tcpsession *s;
  for(s=actsession[0];s;s=s->next){
    if((memcmp(&(c->src), &(s->src), sizeof(c->src)) == 0) && (memcmp(&(c->dst), &(s->dst), sizeof(c->dst)) == 0)){
      break;
    }
    if((memcmp(&(c->src), &(s->dst), sizeof(c->src)) == 0) && (memcmp(&(c->dst), &(s->src), sizeof(c->dst)) == 0)){
      break;
    }
  }
  return(s);
}

tcpsession *new_tcpsession(tcpsession *c)
{
  static uint16_t sid = 0;
  tcpsession *s = malloc(sizeof(tcpsession));
  memcpy(s, c, sizeof(tcpsession));
  opt.tcpsession_count++;
  s->sid = sid++;
  return(s);
}

void del_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  tcpsession *p = c->prev; 
  tcpsession *n = c->next;
  tcpsession *s = c->stok;
  if(c == actsession[0]){
    if(actsession[0] = c->next){
      actsession[0]->prev = NULL;
    }
  }else{
    if(p){
      p->next = n;
    }
    if(n){
      n->prev = p;
    }
  }
  free(c);
  opt.tcpsession_count--;
  del_tcpsession(s);
}

void stok_tcpsession(tcpsession *c, tcpsession *s)
{
  while(c->stok){
    c = c->stok;
  }
  c->stok = new_tcpsession(s);
  c->stok->sid = c->sid;
}

void add_tcpsession(tcpsession *c)
{
  if(c == NULL){
    return;
  }
  while(c->next){
    c = c->next;
  }
  if(c->next = actsession[0]){
    c->next->prev = c;
  }
  actsession[0] = c;
}

void print_tcpsession(tcpsession *s)
{
  struct tm *t;
  char src[64];
  char dst[64];
  char ts[256];
  if(s == NULL){
    return;
  }
  if(s->view == 0){
    t = localtime(&(s->ts.tv_sec));
    sprintf(src, "%s:%u", inet_ntoa(s->src.in.sin_addr), s->src.in.sin_port);
    sprintf(dst, "%s:%u", inet_ntoa(s->dst.in.sin_addr), s->dst.in.sin_port);
    sprintf(ts,  "%02d:%02d:%02d.%03u", t->tm_hour, t->tm_min, t->tm_sec, s->ts.tv_usec/1000);
    printf("[%05d] %s %s -> %s %s\n", s->sid, ts, src, dst, tcp_flag_str(s->flags));
    s->view = 1;
  }
  print_tcpsession(s->stok);
}

void miruo_tcp_session(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
  ethhdr     eh;
  iphdr      ih;
  tcphdr     th;
  u_char     *q;
  u_char     *t;
  tcpsession *c;
  tcpsession  s;

  q = ethhdr_read(&eh, (u_char *)p);
  q = iphdr_read(&ih,  q);
  t = tcphdr_read(&th, q);
  memset(&s, 0, sizeof(s));
  memcpy(&(s.ts), &(h->ts), sizeof(struct timeval));
  memcpy(&(s.src.in.sin_addr), &(ih.src), sizeof(struct in_addr));
  memcpy(&(s.dst.in.sin_addr), &(ih.dst), sizeof(struct in_addr));
  s.src.in.sin_port = th.sport;
  s.dst.in.sin_port = th.dport;
  s.flags = th.flags & 23;
  c = get_tcpsession(&s);

  /****** SYN ******/
  if(s.flags == 2){
    if(c){
      print_tcpsession(c);
    }else{
      c = new_tcpsession(&s);
      c->state = MIRUO_STATE_TCP_SYN;
      add_tcpsession(c);
      print_tcpsession(c);
    }
    return;
  }

  /***** Not Connect *****/
  if(c == NULL){
    return;
  }

  /****** ACK *****/
  if(s.flags == 16){
    switch(c->state){
      case MIRUO_STATE_TCP_SYNACK:
        c->state = MIRUO_STATE_TCP_EST;
        stok_tcpsession(c, &s);
        print_tcpsession(c);
        break;
      case MIRUO_STATE_TCP_FINACK:
        stok_tcpsession(c, &s);
        print_tcpsession(c);
        del_tcpsession(c);
        break;
    }
  }

  /***** SYN/ACK *****/
  if(s.flags == 18){
    stok_tcpsession(c, &s);
    if(c->state == MIRUO_STATE_TCP_SYN){
      print_tcpsession(c);
      c->state = MIRUO_STATE_TCP_SYNACK;
    }else{
      print_tcpsession(c);
    }
    return;
  }

  if(s.flags == 1){ /* FIN */
    c->state = MIRUO_STATE_TCP_FIN;
    stok_tcpsession(c, &s);
    print_tcpsession(c);
    return;
  }

  if(s.flags == 17){ /* FIN/ACK */
    stok_tcpsession(c, &s);
    print_tcpsession(c);
    switch(c->state){
      case MIRUO_STATE_TCP_EST:
        c->state = MIRUO_STATE_TCP_FIN;
        break;
      case MIRUO_STATE_TCP_FIN:
        c->state = MIRUO_STATE_TCP_FINACK;
        break;
      default:
        break;
    }
  }
  if(s.flags == 4){ /* RST */
    stok_tcpsession(c, &s);
    print_tcpsession(c);
    del_tcpsession(c);
  }
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

int miruo_init()
{
  memset(&opt, 0, sizeof(opt));
  memset(actsession, 0, sizeof(actsession));
  tcpsession_free = NULL;
  strcpy(opt.dev,"eth0");
}

int main(int argc, char *argv[])
{
  int i;
  int r;
  int m;
  char expr[1024];
  char filter[1024];
  char errmsg[2046];
  pcap_t *pc;
  struct bpf_program pf;
  bpf_u_int32  ln = 0;
  bpf_u_int32  nm = 0;
  pcap_handler hn = NULL;

  miruo_init();
  memset(expr,   0, sizeof(expr));
  memset(filter, 0, sizeof(filter));
  memset(errmsg, 0, sizeof(errmsg));
  while((r = getopt_long(argc, argv, "hVTvi:", get_optlist(), NULL)) != -1){
    switch(r){
      case 'h':
        usage();
        exit(0);
      case 'V':
        version();
        exit(0);
      case 'v':
        opt.vlevel++;
        break;
      case 'T':
        m = MIRUO_MODE_TCP_SESSION;
        hn = miruo_tcp_session;
        strcpy(filter, "tcp");
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
    if(strlen(expr)){
      strcat(expr, " ");
    }
    strcat(expr, argv[i]);
  }
  if(strlen(filter)){
    if(strlen(expr)){
      strcat(expr, " and ");
    }
    strcat(expr,  filter);
  }

  printf("vlevel: %d\n", opt.vlevel);
  pc = pcap_open_live(opt.dev, 1600, 1, 1000, errmsg);
  if(!pc){
    fprintf(stderr, "pcap_open_live error: %s %s\n", errmsg, opt.dev);
    return(1);
  }
  if(pcap_lookupnet(opt.dev, &ln, &nm, errmsg)){
    fprintf(stderr, "pcap_looknet error: %s\n", errmsg);
    return(1);
  }
  if(pcap_compile(pc, &pf, expr, 0, nm)){
    fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(pc));
    return(1);
  }
  if(pcap_setfilter(pc, &pf)){
    fprintf(stderr, "pcap_setfilter error: %s\n", pcap_geterr(pc));
    return(1);
  }
  if(pcap_loop(pc, 0, hn, NULL)){
    fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(pc));
    return(1);
  }
  pcap_close(pc);
  return(0);
}

