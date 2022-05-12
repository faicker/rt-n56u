#ifndef CHINADNS_NG_DNLUTILS_H
#define CHINADNS_NG_DNLUTILS_H

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "uthash.h"
#undef _GNU_SOURCE

/* hash entry typedef */
typedef struct {
    myhash_hh hh;
    char dname[];
} dnlentry_t;

typedef struct {
    myhash_hh hh;
    uint8_t ip[16];
    char dname[];    // key
} hostsv6entry_t;

typedef struct {
    myhash_hh hh;
    uint8_t ip[4];
    char dname[];    // key
} hostsv4entry_t;

typedef struct {
    bool v6;
    char dname[];
} hosts_lookup_key_t;

/* initialize domain-name-list from file */
size_t dnl_init(const char *filename,  dnlentry_t **head);

/* check if the given domain name matches */
bool dnl_ismatch(const char *domainname, dnlentry_t *head);

/* initialize domain-name-list from file */
size_t hosts_init(const char *filename,  hostsv4entry_t **v4_head, hostsv6entry_t **v6_head);

/* check if the given domain name matches */
bool hosts_v4_ismatch(const char *domainname, hostsv4entry_t *head, hostsv4entry_t **found);
bool hosts_v6_ismatch(const char *domainname, hostsv6entry_t *head, hostsv6entry_t **found);

#endif
