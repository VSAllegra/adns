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
#define BACKLOG 5

#define USAGE \
    "Usage:` adns [-h] [-i IP_ADDRESS] [-p PORT] [-t] ZONE_FILE\n" \
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


struct zone {
    struct rr *rrs;
};

struct rr {
    char domain[MAX_DOMAIN_SIZE];              
    char ip_str[INET_ADDRSTRLEN]; /* includes space for nul */
    UT_hash_handle hh;
}; 


static void
rr_free(struct rr *rr)
{
    free(rr);
}


static struct rr *
rr_from_str(char *s)
{
    MU_NEW(rr, rr);
    char *p, *tok;
    int col;
    size_t len;

    for (col = 0, p = s; /* BLANK */; col++, p = NULL) {
        tok = strtok(p, " ");
        if (tok == NULL)
            break;

        switch (col) {
        case 0:
            len = mu_strlcpy(rr->domain, tok, sizeof(rr->domain));
            if (len >= sizeof(rr->domain))
                goto fail;
            break;
        case 1:
            len = mu_strlcpy(rr->ip_str, tok, sizeof(rr->ip_str));
            if (len >= sizeof(rr->ip_str))
                goto fail;
            break;
        default:
            goto fail;
        }
    }

    if (col == 2)
        goto succeed;
fail:
    rr_free(rr);
    return NULL;

succeed:
    return rr;
}


static void
zone_init(struct zone *zone)
{
    mu_memzero_p(zone);
}


static void
zone_deinit(struct zone *zone)
{
    struct rr *rr, *tmp;

    HASH_ITER(hh, zone->rrs, rr, tmp) {
        HASH_DEL(zone->rrs, rr);
        rr_free(rr);
    }
}


/* Return rr for domain, or NULL if the domain does not exist */
static struct rr *
zone_get_rr(const struct zone *zone, const char *domain_name)
{
    struct rr *rr = NULL;

    HASH_FIND_STR(zone->rrs, domain_name, rr);
 
    return rr;
}


/* 
 * If the domain key already exists in a previous rr, replace
 * that rr and return the previous one
 */
static struct rr *
zone_add_rr(struct zone *zone, struct rr *rr)
{
    struct rr *existent = NULL;

    HASH_REPLACE_STR(zone->rrs, domain, rr, existent);

    return existent;
}


static void
zone_print(const struct zone *zone)
{
    struct rr *rr, *tmp;

    HASH_ITER(hh, zone->rrs, rr, tmp) {
        mu_pr_debug("rr {\"%s\" => \"%s\"}",  rr->domain, rr->ip_str);
    } 
}


static void
zone_read_file(struct zone *zone, const char *zone_file)
{
    FILE *fh = NULL;
    ssize_t len_ret = 0;
    size_t len = 0;
    char * line = NULL;
    struct rr *rr = NULL, *existent_rr = NULL;

    fh = fopen(zone_file, "r");
    if (fh == NULL) {
        mu_die_errno(errno, "can't open zone file \"%s\"",
                zone_file);
    }

    while (1) {
        len_ret = getline(&line, &len, fh);
        if (len_ret == -1)
            goto out;

        mu_str_chomp(line);
        rr = rr_from_str(line);
        if (rr == NULL) {
            mu_die("zone file \"%s\" has invalid line: \"%s\"",
                    zone_file, line);
        }

        existent_rr = zone_add_rr(zone, rr);
        if (existent_rr != NULL)
            rr_free(existent_rr);
    }

    if (HASH_COUNT(zone->rrs) == 0)
        mu_die("zone file has no resource records");

out:
    if (ferror(fh))
        mu_die("error reading zone file \"%s\"", zone_file);

    free(line); 
    fclose(fh);
}

static void
process_message(const struct zone * zone, struct message *msg)
{
    struct rr * rr = NULL;

    if (msg->type == QTYPE_A) {
        rr = zone_get_rr(zone, msg->body);
        if (rr == NULL) {
            message_set_error(msg, RCODE_NXDOMAIN);
        } else {
            msg->type = RCODE_NOERROR;
            message_set_body(msg, rr->ip_str);
        }
    } else {
        message_set_error(msg, RCODE_FORMERR);
    }
}

static void
serve_forever_tcp4(int sk, struct zone * zone)
{
    struct sockaddr_in addr;
    socklen_t addr_size;
    int conn;
    char peer_str[MU_LIMITS_MAX_INET_STR_SIZE] = { 0 };
    int err;
    uint8_t hdr[HEADER_SIZE] = { 0 };
    size_t total;
    struct message msg;
    ssize_t n;
    uint8_t buf[MAX_MESSAGE_SIZE] = { 0 };


    while (1) {
        addr_size = sizeof(addr);
        conn = accept(sk, (struct sockaddr *)&addr, &addr_size);
        if (conn == -1)
            mu_die_errno(errno, "accept");
        
        mu_sockaddr_in_to_str(&addr, peer_str, sizeof(peer_str));
        mu_pr_debug("%s: connected", peer_str);

        /* receive header */
        err = mu_read_n(conn, hdr, sizeof(hdr), &total);
        if (err < 0){
            mu_stderr_errno(-err, "%s: error handling TCP request", peer_str);
            goto request_done;
        } else if (total != sizeof(hdr)){
            mu_stderr_errno(-err, "%s: disconnected: failed to receive complete header", peer_str);
            goto request_done;
        }

        /* parse header */
        n = message_deserialize_header(&msg, hdr, sizeof(hdr));
        if (n < 0) {
            mu_stderr("%s: malformed message header", peer_str);
            goto request_done;
        }

        if (msg.body_len == 0) {
            mu_stderr("%s: zero-length body", peer_str);
            message_set_error(&msg, RCODE_FORMERR);
            goto send_response;
        }

        if (msg.body_len > MAX_BODY_LEN) {
            mu_stderr("%s: body length too large (%" PRIu16 ")", peer_str, msg.body_len);
            message_set_error(&msg, RCODE_FORMERR);
            goto send_response;
        }


        /* receive body */
        err = mu_read_n(conn, msg.body, msg.body_len, &total);
        if (err < 0) {
            mu_stderr_errno(-err, "%s: error handling TCP request", peer_str);
            goto request_done;
        } else if (total != msg.body_len) {
            mu_stderr_errno(-err, "%s: disconnected: failed to receive complete body", peer_str);
            goto request_done;
        }

        printf("%s", msg.body);
        mu_pr_debug("%s: request: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", query=\"%s\"",
            peer_str, msg.id, msg.type, msg.body_len, msg.body);


        process_message(zone, &msg);

      
send_response:
        mu_pr_debug("%s: request: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", answer=\"%s\"",
            peer_str, msg.id, msg.type, msg.body_len, msg.body);

        n = message_serialize(&msg, buf, sizeof(buf));
        if (n < 0)
            mu_die("message_serialize");

        err= mu_write_n(conn, buf, (size_t)n, &total);
        if (err < 0)
            mu_stderr_errno(-err, "%s: TCP send fialed", peer_str);

request_done:
        close(conn);
    }

}


static void
serve_forever_udp4(int sk, struct zone * zone)
{
    struct sockaddr_in addr;
    socklen_t addr_size;
    int conn;
    char peer_str[MU_LIMITS_MAX_INET_STR_SIZE] = { 0 };
    int err;
    uint8_t hdr[HEADER_SIZE] = { 0 };
    size_t total;
    struct message msg;
    ssize_t n;
    uint8_t buf[MAX_MESSAGE_SIZE] = { 0 };


    while (1) {
        addr_size = sizeof(addr);
        conn = accept(sk, (struct sockaddr *)&addr, &addr_size);
        if (conn == -1)
            mu_die_errno(errno, "accept");
        
        mu_sockaddr_in_to_str(&addr, peer_str, sizeof(peer_str));
        mu_pr_debug("%s: connected", peer_str);

        /* receive header */
        err = mu_read_n(conn, hdr, sizeof(hdr), &total);
        if (err < 0){
            mu_stderr_errno(-err, "%s: error handling UDP request", peer_str);
            goto request_done;
        } else if (total != sizeof(hdr)){
            mu_stderr_errno(-err, "%s: disconnected: failed to receive complete header", peer_str);
            goto request_done;
        }

        /* parse header */
        n = message_deserialize_header(&msg, hdr, sizeof(hdr));
        if (n < 0) {
            mu_stderr("%s: malformed message header", peer_str);
            goto request_done;
        }

        if (msg.body_len == 0) {
            mu_stderr("%s: zero-length body", peer_str);
            message_set_error(&msg, RCODE_FORMERR);
            goto send_response;
        }

        if (msg.body_len > MAX_BODY_LEN) {
            mu_stderr("%s: body length too large (%" PRIu16 ")", peer_str, msg.body_len);
            message_set_error(&msg, RCODE_FORMERR);
            goto send_response;
        }


        /* receive body */
        err = mu_read_n(conn, msg.body, msg.body_len, &total);
        if (err < 0) {
            mu_stderr_errno(-err, "%s: error handling UDP request", peer_str);
            goto request_done;
        } else if (total != msg.body_len) {
            mu_stderr_errno(-err, "%s: disconnected: failed to receive complete body", peer_str);
            goto request_done;
        }

        printf("%s", msg.body);
        mu_pr_debug("%s: request: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", query=\"%s\"",
            peer_str, msg.id, msg.type, msg.body_len, msg.body);


        process_message(zone, &msg);
        goto send_response;

      
send_response:
        mu_pr_debug("%s: request: id=%" PRIu32 ", type=%" PRIu16 ", body_len=%" PRIu16 ", answer=\"%s\"",
            peer_str, msg.id, msg.type, msg.body_len, msg.body);

        n = message_serialize(&msg, buf, sizeof(buf));
        if (n < 0)
            mu_die("message_serialize");

        err= mu_write_n(conn, buf, (size_t)n, &total);
        if (err < 0)
            mu_stderr_errno(-err, "%s: TCP send fialed", peer_str);

request_done:
        close(conn);
    }

}


static int
server_create(const char *ip, const char *port, bool is_tcp)
{
    int sk;
    struct sockaddr_in sa;
    int err;

    sk = socket(AF_INET, is_tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (sk == -1)
        mu_die_errno(errno, "socket");
    
    if (is_tcp)
        mu_reuseaddr(sk);

    mu_init_sockaddr_in(&sa, ip, port);
    err = bind(sk, (struct sockaddr *)&sa, sizeof(sa));
    if (err == -1)
        mu_die_errno(errno, "bind");
    
    if (is_tcp) {
        err = listen(sk, BACKLOG);
        if (err == -1)
            mu_die_errno(errno, "listen");
    }

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
    char *port_str = NULL;
    int sk;
    struct zone zone;

    while (1) {
        opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'h':   /* help */
            usage(0);
            break;
        case 'i':
            ip_str = mu_strdup(optarg);
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
    if (nargs != 1)
        mu_die("expected one positional argument (ZONE_FILE), but found %d", nargs);

    zone_init(&zone);
    zone_read_file(&zone, argv[optind]);
    //zone_print(&zone);

    sk = server_create(ip_str != NULL ? ip_str : DEFAULT_IP_STR,  
            port_str != NULL ? port_str : DEFAULT_PORT_STR, 
            is_tcp);
    
    if (is_tcp){
        serve_forever_tcp4(sk, &zone);
    } else {
        serve_forever_udp4(sk, &zone);
    }

    free(ip_str);
    free(port_str);
    zone_deinit(&zone);

    return 0;
}