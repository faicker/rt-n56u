#define _GNU_SOURCE
#include "dnlutils.h"
#include "dnsutils.h"
#include "logutils.h"
#include "netutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#undef _GNU_SOURCE

/* a very simple memory pool (alloc only) */
static void* mempool_alloc(size_t length) {
    static void  *mempool_buffer = NULL;
    static size_t mempool_length = 0;
    if (mempool_length < length) {
        /* arg.length must be <= 4096 */
        mempool_length = 4096; /* block size */
        mempool_buffer = malloc(mempool_length);
    }
    mempool_buffer += length;
    mempool_length -= length;
    return mempool_buffer - length;
}

/* handling dname matching pattern */
// com -> com
// a.com -> a/com
// a.b.c.com -> a/b/c/com
// a.b.c.d.com -> b/c/d/com
static inline char* dnl_pattern_strip(char *pattern) {
    if (pattern[0] == '.' || pattern[strlen(pattern) - 1] == '.') return NULL;
    for (int i = 0; i < 4; ++i) {
        char *sepptr = strrchr(pattern, '.');
        if (sepptr) {
            *sepptr = '/';
            if (i == 3) pattern = sepptr + 1;
        } else if (i == 0) {
            return pattern;
        } else {
            break;
        }
    }
    return pattern;
}

/* split dname pattern, array length is 3 */
// c/com -> 0=com
// b/c/com -> 1 = c/com, 0=com
// a/b/c/com -> 2 = b/c/com,  1 = c/com, 0=com
static inline void dnl_pattern_split(const char *pattern, const char* subpattern_array[]) {
    int slashchar_count = 0;
    for (int i = 0; pattern[i]; ++i) {
        if (pattern[i] == '/') ++slashchar_count;
    }
    if (slashchar_count == 1) {
        subpattern_array[0] = strchr(pattern, '/') + 1;
    } else if (slashchar_count == 2) {
        subpattern_array[1] = strchr(pattern, '/') + 1;
        subpattern_array[0] = strchr(subpattern_array[1], '/') + 1;
    } else if (slashchar_count == 3) {
        subpattern_array[2] = strchr(pattern, '/') + 1;
        subpattern_array[1] = strchr(subpattern_array[2], '/') + 1;
        subpattern_array[0] = strchr(subpattern_array[1], '/') + 1;
    }
}

/* convert domain name, array length is 4 */
// b.com => 1=b/com 0=com
// a.b.com => 2=a/b/com 1=b/com 0=com
// a.b.c.com => 3=a/b/c/com 2=b/c/com 1=c/com 0=com
// a.b.c.d.com => 3=b/c/d/com 2 = c/d/com 1=d/com 0=com
static inline void dnl_input_convert(char *fulldomain, const char* subdomain_array[]) {
    if (fulldomain[0] == '.') return;
    int replace_count = 0;
    while (replace_count < 5) {
        char *sepptr = strrchr(fulldomain, '.');
        if (!sepptr) break;
        *sepptr = '/';
        ++replace_count;
    }
    switch (replace_count) {
        case 1:
            subdomain_array[1] = fulldomain;
            subdomain_array[0] = strchr(fulldomain, '/') + 1;
            break;
        case 2:
            subdomain_array[2] = fulldomain;
            subdomain_array[1] = strchr(fulldomain, '/') + 1;
            subdomain_array[0] = strchr(subdomain_array[1], '/') + 1;
            break;
        case 3:
            subdomain_array[3] = fulldomain;
            subdomain_array[2] = strchr(fulldomain, '/') + 1;
            subdomain_array[1] = strchr(subdomain_array[2], '/') + 1;
            subdomain_array[0] = strchr(subdomain_array[1], '/') + 1;
            break;
        case 4:
            subdomain_array[3] = strchr(fulldomain, '/') + 1;
            subdomain_array[2] = strchr(subdomain_array[3], '/') + 1;
            subdomain_array[1] = strchr(subdomain_array[2], '/') + 1;
            subdomain_array[0] = strchr(subdomain_array[1], '/') + 1;
            break;
    }
}

/* initialize domain-name-list from file */
size_t dnl_init(const char *filename, dnlentry_t **headentry) {
    FILE *fp = NULL;
    if (strcmp(filename, "-") == 0) {
        fp = stdin;
    } else {
        fp = fopen(filename, "r");
        if (!fp) {
            LOGERR("[dnl_init] failed to open '%s': (%d) %s", filename, errno, strerror(errno));
            exit(errno);
        }
    }

    char strbuf[DNS_DOMAIN_NAME_MAXLEN];
    while (fscanf(fp, "%253s", strbuf) > 0) {
        char *dname = dnl_pattern_strip(strbuf);
        if (!dname) continue;

        dnlentry_t *entry = NULL;
        MYHASH_GET(*headentry, entry, dname, strlen(dname));
        if (entry) continue;

        entry = mempool_alloc(sizeof(dnlentry_t) + strlen(dname) + 1);
        strcpy(entry->dname, dname);
        MYHASH_ADD(*headentry, entry, entry->dname, strlen(entry->dname));
    }
    if (fp != stdin) fclose(fp);

    dnlentry_t *curentry = NULL, *tmpentry = NULL;
    MYHASH_FOR(*headentry, curentry, tmpentry) {
        const char* subpattern_array[3] = {0};
        dnl_pattern_split(curentry->dname, subpattern_array);
        for (int i = 0; i < 3 && subpattern_array[i]; ++i) {
            dnlentry_t *findentry = NULL;
            MYHASH_GET(*headentry, findentry, subpattern_array[i], strlen(subpattern_array[i]));
            if (findentry) {
                MYHASH_DEL(*headentry, curentry);
                break;
            }
        }
    }
    return MYHASH_CNT(*headentry);
}

/* check if the given domain name matches */
bool dnl_ismatch(const char *domainname, dnlentry_t *headentry) {
    const char* subdomain_array[4] = {0};
    char name[DNS_DOMAIN_NAME_MAXLEN] = {0};
    strcpy(name, domainname);
    dnl_input_convert(name, subdomain_array);

    if (headentry) {
        for (int i = 0; i < 4 && subdomain_array[i]; ++i) {
            dnlentry_t *findentry = NULL;
            MYHASH_GET(headentry, findentry, subdomain_array[i], strlen(subdomain_array[i]));
            if (findentry) return true;
        }
    }

    return false;
}

static void add_v4_entry(hostsv4entry_t **headentry, char *dname, size_t dname_len, uint8_t *buf) {
    hostsv4entry_t *entry = NULL;
    MYHASH_GET(*headentry, entry, dname, dname_len);
    if (entry) return;

    entry = mempool_alloc(sizeof(hostsv4entry_t) + dname_len + 1);
    memcpy(entry->ip, buf, IPV4_BINADDR_LEN);
    strcpy(entry->dname, dname);
    MYHASH_ADD(*headentry, entry, entry->dname, dname_len);
}

static void filter_v4_entry(hostsv4entry_t **headentry) {
    hostsv4entry_t *curentry = NULL, *tmpentry = NULL;
    MYHASH_FOR(*headentry, curentry, tmpentry) {
        const char* subpattern_array[3] = {0};
        dnl_pattern_split(curentry->dname, subpattern_array);
        for (int i = 0; i < 3 && subpattern_array[i]; ++i) {
            hostsv4entry_t *findentry = NULL;
            MYHASH_GET(*headentry, findentry, subpattern_array[i], strlen(subpattern_array[i]));
            if (findentry) {
                MYHASH_DEL(*headentry, curentry);
                break;
            }
        }
    }
}

static void add_v6_entry(hostsv6entry_t **headentry, char *dname, size_t dname_len, uint8_t *buf) {
    hostsv6entry_t *entry = NULL;
    MYHASH_GET(*headentry, entry, dname, dname_len);
    if (entry) return;

    entry = mempool_alloc(sizeof(hostsv6entry_t) + dname_len + 1);
    memcpy(entry->ip, buf, IPV6_BINADDR_LEN);
    strcpy(entry->dname, dname);
    MYHASH_ADD(*headentry, entry, entry->dname, dname_len);
}

static void filter_v6_entry(hostsv6entry_t **headentry) {
    hostsv6entry_t *curentry = NULL, *tmpentry = NULL;
    MYHASH_FOR(*headentry, curentry, tmpentry) {
        const char* subpattern_array[3] = {0};
        dnl_pattern_split(curentry->dname, subpattern_array);
        for (int i = 0; i < 3 && subpattern_array[i]; ++i) {
            hostsv6entry_t *findentry = NULL;
            MYHASH_GET(*headentry, findentry, subpattern_array[i], strlen(subpattern_array[i]));
            if (findentry) {
                MYHASH_DEL(*headentry, curentry);
                break;
            }
        }
    }
}

/* initialize domain-name-list from file */
size_t hosts_init(const char *filename, hostsv4entry_t **v4_headentry, hostsv6entry_t **v6_headentry) {
    FILE *fp = NULL;
    fp = fopen(filename, "r");
    if (!fp) {
        LOGERR("[hosts_init] failed to open '%s': (%d) %s", filename, errno, strerror(errno));
        exit(errno);
    }

    char *linebuf = NULL;
    size_t linesiz = 0;
    ssize_t linelen = 0;
    while ((linelen = getline(&linebuf, &linesiz, fp)) != -1) {
        linebuf[linelen-1] = '\0';
        char *pch = strtok(linebuf, " ");
        if (!pch) continue;
        uint8_t buf[IPV6_BINADDR_LEN] = {0};
        bool is_v6;
        if (!ip_str_to_bin(pch, buf, &is_v6)) continue;

        pch = strtok(NULL, " ");
        while (pch != NULL) {
            char *dname = dnl_pattern_strip(pch);
            if (!dname) continue;
            size_t dname_len = strlen(dname);

            if (!is_v6) {
                add_v4_entry(v4_headentry, dname, dname_len, buf);
            } else {
                add_v6_entry(v6_headentry, dname, dname_len, buf);
            }
            pch = strtok(NULL, " ");
        }
    }
    free(linebuf);
    fclose(fp);

    filter_v4_entry(v4_headentry);
    filter_v6_entry(v6_headentry);

    return MYHASH_CNT(*v4_headentry) + MYHASH_CNT(*v6_headentry);
}

/* check if the given domain name matches */
bool hosts_v4_ismatch(const char *domainname, hostsv4entry_t *headentry, hostsv4entry_t **found) {
    const char* subdomain_array[4] = {0};
    char name[DNS_DOMAIN_NAME_MAXLEN] = {0};
    strcpy(name, domainname);
    dnl_input_convert(name, subdomain_array);

    if (headentry) {
        hostsv4entry_t *findentry = NULL;
        for (int i = 0; i < 4 && subdomain_array[i]; ++i) {
            MYHASH_GET(headentry, findentry, subdomain_array[i], strlen(subdomain_array[i]));
            if (findentry) {
                if (found) *found = findentry;
                return true;
            }
        }
    }

    return false;
}

bool hosts_v6_ismatch(const char *domainname, hostsv6entry_t *headentry, hostsv6entry_t **found) {
    const char* subdomain_array[4] = {0};
    char name[DNS_DOMAIN_NAME_MAXLEN] = {0};
    strcpy(name, domainname);
    dnl_input_convert(name, subdomain_array);

    if (headentry) {
        hostsv6entry_t *findentry = NULL;
        for (int i = 0; i < 4 && subdomain_array[i]; ++i) {
            MYHASH_GET(headentry, findentry, subdomain_array[i], strlen(subdomain_array[i]));
            if (findentry) {
                if (found) *found = findentry;
                return true;
            }
        }
    }

    return false;
}
