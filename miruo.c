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

u_char *ethhdr_read(ethhdr *h, u_char *p, uint32_t *l)
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

u_char *sllhdr_read(sllhdr *h, u_char *p, uint32_t *l)
{
  //printf("-----------------------------------------------\n");
  //dump_data(p, 32);
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

void print_tcpsession(tcpsession *s, int flag)
{
  struct tm *t;
  char src[64];
  char dst[64];
  char ts[256];
  if(s == NULL){
    return;
  }
  if((flag == 0) && (s->view == 0)){
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
  print_tcpsession(s->stok, 1);
}

void miruo_tcp_session(u_char *u, const struct pcap_pkthdr *h, const u_char *p)
{
  ethhdr     eh;
  sllhdr     sh;
  iphdr      ih;
  tcphdr     th;
  u_char     *q;
  uint32_t    l;
  tcpsession *c;
  tcpsession  s;

  l = h->caplen;
  switch(opt.lktype){
    case 1:   /* Ethernet */
      q = ethhdr_read(&eh, (u_char *)p, &l);
      if(q == NULL){
        fprintf(stderr, "error: Ether Head Error\n");
        return;
      }
      if(eh.type != 0x0800){
        fprintf(stderr, "error: eth error type=%d\n", eh.type);
        return;
      }
      break;
    case 113: /* Linux cooked */
      q = sllhdr_read(&sh, (u_char *)p, &l);
      if(q == NULL){
        fprintf(stderr, "error: Linux cooked Head Error\n");
        return;
      }
      if(sh.type != 0x0800){
        fprintf(stderr, "error: sll error type=%d\n", sh.type);
        return;
      }
      break;
    default:
      q = NULL;
      fprintf(stderr, "error: not support datalink %s\n", opt.lkdesc);
      pcap_breakloop(opt.p);
      return;
  }

  q = iphdr_read(&ih, q, &l);
  if(q == NULL){
    fprintf(stderr, "error: IP Head Read error\n");
    return;
  }
  if(ih.Protocol != 6){
    printf("error: IP error protocol=%d\n", ih.Protocol);
    return;
  }
  q = tcphdr_read(&th, q, &l);
  if(q == NULL){
    fprintf(stderr, "error: TCP Head Read error\n");
    return;
  }
  memset(&s, 0, sizeof(s));
  memcpy(&(s.ts), &(h->ts), sizeof(struct timeval));
  memcpy(&(s.src.in.sin_addr), &(ih.src), sizeof(struct in_addr));
  memcpy(&(s.dst.in.sin_addr), &(ih.dst), sizeof(struct in_addr));
  s.src.in.sin_port = th.sport;
  s.dst.in.sin_port = th.dport;
  s.flags = th.flags;
  th.flags &= 23;
  c = get_tcpsession(&s);

  /****** SYN ******/
  if(th.flags == 2){
    if(c){
      // SYNの再送を検出
      stok_tcpsession(c, &s);
      print_tcpsession(c, 1);
    }else{
      c = new_tcpsession(&s);
      c->state = MIRUO_STATE_TCP_SYN;
      add_tcpsession(c);
      print_tcpsession(c, opt.verbose);
    }
    return;
  }

  /***** Not Connect *****/
  if(c == NULL){
    return;
  }

  /****** ACK *****/
  if(th.flags == 16){
    switch(c->state){
      case MIRUO_STATE_TCP_SYNACK:
        c->state = MIRUO_STATE_TCP_EST;
        stok_tcpsession(c, &s);
        print_tcpsession(c, 0);
        break;
      case MIRUO_STATE_TCP_FINACK:
        stok_tcpsession(c, &s);
        print_tcpsession(c, 0);
        del_tcpsession(c);
        break;
    }
    return;
  }

  /***** SYN/ACK *****/
  if(th.flags == 18){
    stok_tcpsession(c, &s);
    if(c->state == MIRUO_STATE_TCP_SYN){
      c->state = MIRUO_STATE_TCP_SYNACK;
      print_tcpsession(c, 0);
    }else{
      print_tcpsession(c, 1);
    }
    return;
  }

  /***** FIN *****/
  if(th.flags == 1){
    stok_tcpsession(c, &s);
    switch(c->state){
      case MIRUO_STATE_TCP_EST:
        c->state = MIRUO_STATE_TCP_FIN;
        print_tcpsession(c, 0);
        break;
      default:
        print_tcpsession(c, 1);
        break;
    }
    return;
  }

  /***** FIN/ACK *****/
  if(th.flags == 17){
    stok_tcpsession(c, &s);
    switch(c->state){
      case MIRUO_STATE_TCP_EST:
        c->state = MIRUO_STATE_TCP_FIN;
        print_tcpsession(c, 0);
        break;
      case MIRUO_STATE_TCP_FIN:
        c->state = MIRUO_STATE_TCP_FINACK;
        print_tcpsession(c, 0);
        break;
      default:
        print_tcpsession(c, 1);
        break;
    }
    return;
  }

  /***** RST *****/
  if(th.flags == 4){
    stok_tcpsession(c, &s);
    print_tcpsession(c, 1);
    del_tcpsession(c);
    return;
  }
  stok_tcpsession(c, &s);
  print_tcpsession(c, 0);
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
}

int miruo_init()
{
  char *p;
  char  e[PCAP_ERRBUF_SIZE];
  memset(&opt, 0, sizeof(opt));
  memset(actsession, 0, sizeof(actsession));
  tcpsession_free = NULL;
  p = pcap_lookupdev(e);
  if(p == NULL){
    fprintf(stderr,"%s: %s\n", __func__, e);
  }else{
    strcpy(opt.dev, p);
  }
  miruo_signal();
  opt.pksize = 96;
  opt.promisc = 1;
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
  while((r = getopt_long(argc, argv, "hVvi:m:r:", get_optlist(), NULL)) != -1){
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
    fprintf(stderr, "pcap_compile error: %s\n", pcap_geterr(opt.p));
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

  printf("listening on %s, link-type %s (%s), capture size %d bytes\n", opt.dev, opt.lkname, opt.lkdesc, opt.pksize);

  if(pcap_loop(opt.p, -1, hn, NULL) == -1){
    fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(opt.p));
  }

  pcap_close(opt.p);
  opt.p = NULL;
  return(0);
}

