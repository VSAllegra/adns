#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mu.h"
#include "common.h"
#include "uthash.h"

#define DEFAULT_IP_STR "0.0.0.0"


#define USAGE \
    "Usage:` adns [-h] [-i IP_ADDRESS] [-p PORT] [-t] QUERY\n" \
    "\n" \
    "A simplified version of a DNS server for IPv4.\n" \
    "\n" \
    "optional arguments\n" \
    "   -h, --help\n" \
    "       Show usage statement and exit.\n" \
    "\n" \
    "   -i, --interface IP_ADDRESS\n" \
    "       The interface to listen on.\n" \
    "       (default: INADDR_ANY)\n" \
    "\n" \
    "   -p, --port PORT\n" \
    "       The port to listen on.\n" \
    "       (default: 9514)\n" \
    "\n" \
    "   -t, --tcp\n" \
    "       Use TCP instead of UDP."


static int
tcp_lookup(int sk, const int qtype, const char * query ){
    uint8_t buf[MAX_MESSAGE_SIZE] = { 0 };
    char peer_str[MU_LIMITS_MAX_INET_STR_SIZE] = { 0 };
    uint8_t hdr[HEADER_SIZE] = { 0 };
    int err;
    size_t total;
    struct message msg;
    ssize_t n;

    msg.type = qtype;
    message_set_body(&msg, query);
    //mu_pr_debug("%s: to_send: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", answer=\"%s\"",
        //peer_str, msg.id, msg.type, msg.body_len, msg.body);
    n = message_serialize(&msg, buf, sizeof(buf));
    if (n < 0)
        mu_die("message_serialize");
    
    err = mu_write_n(sk, buf, (size_t)n, &total);
    if (err < 0)
        mu_stderr_errno(-err, "%s: TCP send fialed", peer_str); 

    err = mu_read_n(sk, hdr, sizeof(hdr), &total);
    if (err < 0){
        mu_stderr_errno(-err, "%s: error handling UDP request", peer_str);
    } else if (total != sizeof(hdr)){
        mu_stderr_errno(-err, "%s: disconnected: failed to receive complete header", peer_str);
    }

    /* parse header */
    n = message_deserialize_header(&msg, hdr, sizeof(hdr));


    /* receive body */
    err = mu_read_n(sk, msg.body, msg.body_len, &total);
    
    if (err < 0) {
        mu_stderr_errno(-err, "%s: error handling TCP request", peer_str);
    } else if (total != msg.body_len) {
        mu_stderr_errno(-err, "%s: disconnected: failed to receive complete body", peer_str);
    } 

    if(sizeof(*query) < 2){
        printf("malformed request\n");
        exit(1);
    }
    else if(msg.body_len == 0){
        printf("not found\n");
        exit(1);
    } else {
        printf("%s\n", msg.body);
    }

    
    //mu_pr_debug("%s: request: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", query=\"%s\"",
        //peer_str, msg.id, msg.type, msg.body_len, msg.body);

 

    return msg.type;
}


static int
udp_lookup(int sk, const int qtype, const char * query ){
    uint8_t buf[MAX_MESSAGE_SIZE] = { 0 };
    char peer_str[MU_LIMITS_MAX_INET_STR_SIZE] = { 0 };
    int err;
    size_t total;
    struct message msg;
    ssize_t n;

    

    msg.type = qtype;
    message_set_body(&msg, query);
    //mu_pr_debug("%s: to_send: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", answer=\"%s\"",
        //peer_str, msg.id, msg.type, msg.body_len, msg.body);
    n = message_serialize(&msg, buf, sizeof(buf));
    if (n < 0)
        mu_die("message_serialize");
    
    err = mu_write_n(sk, buf, (size_t)n, &total);
    if (err < 0)
        mu_stderr_errno(-err, "%s: TCP send fialed", peer_str); 

    
    n = recvfrom(sk, buf, sizeof(buf), 0, NULL, NULL);

    n = message_deserialize(&msg, buf, sizeof(buf));

    if(sizeof(*query) < 2){
        printf("malformed request\n");
        exit(1);
    }
    else if(msg.body_len == 0){
        printf("not found\n");
        exit(1);
    } else {
        printf("%s\n", msg.body);
    }
    
    
    return msg.type;
}


static int
client_create(const char *ip, const char *port, bool is_tcp)
{
    int sk;
    struct sockaddr_in sa;
    int err;
    

    sk = socket(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sk == -1)
        mu_die_errno(errno, "socket");
    
   
    mu_reuseaddr(sk);

    mu_init_sockaddr_in(&sa, ip, port);
    err = connect(sk, (struct sockaddr *)&sa, sizeof(sa));
    if (err == -1)
        mu_die_errno(errno, "connect");
    return sk;
}




static void
usage(int status)
{
    puts(USAGE);
    exit(status);
}


int 
main(int argc,char *argv[])
{
    int opt, nargs;
    const char *short_opts = ":hi:p:t";
    struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"interface", required_argument, NULL, 'i'},
        {"port", required_argument, NULL, 'p'},
        {"tcp", no_argument, NULL, 't'},
        {NULL, 0, NULL, 0}
    };
    bool is_tcp = false;
    char *ip_str = NULL;
    char *query; 
    char *port_str = NULL;
    int sk;

    while (1) {
        opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':   /* help */
            usage(0);
            break;
        case 'p':
            port_str = mu_strdup(optarg);
            break;
        case 't':
            is_tcp = true;
            break;
        case '?':
            mu_die("unknown option %c", optopt);
            break;
        case ':':
            mu_die("missing option argument for option %c", optopt);
            break;
        default:
            mu_panic("unexpected getopt_long return value: %c\n", (char)opt);
        }
    }

    nargs = argc - optind;
    if (nargs  == 1){
        ip_str = mu_strdup(argv[optind]);
        query = "";
    }
    else if (nargs == 2){
        ip_str = mu_strdup(argv[optind]);
        query = mu_strdup(argv[optind + 1]);
    }
    

    sk = client_create(ip_str != NULL ? ip_str : DEFAULT_IP_STR,  
            port_str != NULL ? port_str : DEFAULT_PORT_STR, 
            is_tcp);
    
    if (is_tcp)
        tcp_lookup(sk, QTYPE_A, query);
    else
        udp_lookup(sk, QTYPE_A, query);
    
    free(ip_str);
    free(port_str);


    return 0;
}