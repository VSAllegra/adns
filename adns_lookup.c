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
    zone_print(&zone);

    /* TODO: create server */
    MU_UNUSED(sk);
    MU_UNUSED(is_tcp);

    free(ip_str);
    free(port_str);
    zone_deinit(&zone);

    return 0;
}