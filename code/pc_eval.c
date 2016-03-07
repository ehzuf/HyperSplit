/*
 *     Filename: pc_eval.c
 *  Description: Source file for packet classification evaluation
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *               Chang Chen (ck-cc@hotmail.com)
 *               Xiaohe Hu (huxioahe10@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 *
 *      History:  1. Unified packet classification algorithm / evaluation
 *                   framework design (Xiang Wang & Chang Chen)
 *
 *                2. Add build & search time evaluation in main (Chang Chen)
 *
 *                3. Add range2prefix, prefix2range function
 *                   (Xiang Wang & Chang Chen)
 *
 *                4. Add split_range_rule function (Xiang Wang)
 *
 *                5. Support multi algorithms (Xiaohe Hu)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include "pc_algo.h"
#include "pc_eval.h"

#define swap(a, b) \
    do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)

struct queue_node {
    struct range r;
    struct prefix p;
    STAILQ_ENTRY(queue_node) n;
};

STAILQ_HEAD(queue_head, queue_node);

static void print_help(void);
static void parse_args(int argc, char *argv[]);

static struct {
    char *rule_file;
    char *trace_file;
    char *method;
} cfg;

static struct timeval starttime, stoptime;

int main(int argc, char *argv[])
{
    uint64_t timediff;
    struct rule_set rs;
    struct trace t;
    void *rt = NULL;

    if (argc < 2) {
        print_help();
        exit(-1);
    }

    parse_args(argc, argv);

    /*
     * Building
     */
    if (cfg.rule_file == NULL) {
        fprintf(stderr, "No rules for processing\n");
        exit(-1);
    }

    load_rules(&rs, cfg.rule_file);

    printf("Building\n");

    gettimeofday(&starttime, NULL);
    if (build(&rs, &rt) != 0) { /* TODO: replace NULL with user data */
        fprintf(stderr, "Building failed\n");
        unload_rules(&rs);
        exit(-1);
    }
    gettimeofday(&stoptime, NULL);

    timediff = make_timediff(&starttime, &stoptime);

    printf("Building pass\n");
    printf("Time for building: %lld(us)\n", timediff);

    unload_rules(&rs);

    /*
     * Searching
     */
    if (cfg.trace_file == NULL) {
        cleanup(&rt); /* TODO: replace NULL with user data */
        return 0;
    }

    load_trace(&t, cfg.trace_file);

    printf("Searching\n");

    gettimeofday(&starttime, NULL);
    if (search(&t, &rt) != 0) { /* TODO: replace NULL with user data */
        fprintf(stderr, "Searching failed\n");
        unload_trace(&t);
        cleanup(&rt); /* TODO: replace NULL with user data */
        exit(-1);
    }
    gettimeofday(&stoptime, NULL);

    timediff = make_timediff(&starttime, &stoptime);

    printf("Searching pass\n");
    printf("Time for searching: %lld(us)\n", timediff);
    printf("Searching speed: %lld(pps)\n", (t.num * 1000000ULL) / timediff);

    unload_trace(&t);
    cleanup(&rt); /* TODO: replace NULL with user data */

    return 0;
}

static void print_help(void)
{
    static const char *help =

        "Valid options:\n"
        "  -h, --help         display this help and exit\n"
        "  -r, --rule FILE    specify a rule file for building\n"
        "  -t, --trace FILE   specify a trace file for searching\n"
        "\n";

    printf("%s", help);
    return;
}

static void parse_args(int argc, char *argv[])
{
    int option;
    static const char *optstr = "hr:t:m:";
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"rule", required_argument, NULL, 'r'},
        {"trace", required_argument, NULL, 't'},
        {"method", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };

    while ((option = getopt_long(argc, argv, optstr, longopts, NULL)) != -1) {
        switch (option) {
        case 'h':
            print_help();
            exit(0);

        case 'm':
            if (access(optarg, F_OK) == -1) {
                perror(optarg);
                exit(-1);
            } else {
                if (option == 'm') {
                    cfg.method = atoi(optarg);
                }
                break;
            }

        case 'r':
        case 't':
            if (access(optarg, F_OK) == -1) {
                perror(optarg);
                exit(-1);
            } else {
                if (option == 'r') {
                    cfg.rule_file = optarg;
                } else if (option == 't') {
                    cfg.trace_file = optarg;
                }
                break;
            }

        default:
            print_help();
            exit(-1);
        }
    }

    return;
}

uint64_t make_timediff(struct timeval *start, struct timeval *stop)
{
    return (1000000ULL * stop->tv_sec + stop->tv_usec) -
        (1000000ULL * start->tv_sec + start->tv_usec);
}

void load_rules(struct rule_set *rs, const char *rf)
{
    FILE *rule_fp;
    uint32_t src_ip, src_ip_0, src_ip_1, src_ip_2, src_ip_3, src_ip_mask;
    uint32_t dst_ip, dst_ip_0, dst_ip_1, dst_ip_2, dst_ip_3, dst_ip_mask;
    uint32_t src_port_begin, src_port_end, dst_port_begin, dst_port_end;
    uint32_t proto, proto_mask;
    unsigned int i = 0;

    printf("Loading rules from %s\n", rf);

    if ((rule_fp = fopen(rf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", rf);
        exit(-1);
    }

    rs->rules = calloc(RULE_MAX, sizeof(struct rule));
    if (rs->rules == NULL) {
        perror("Cannot allocate memory for rules");
        exit(-1);
    }
    rs->num = 0;

    while (!feof(rule_fp)) {
        if (i >= RULE_MAX) {
            fprintf(stderr, "Too many rules\n");
            exit(-1);
        }

        if (fscanf(rule_fp, RULE_FMT,
            &src_ip_0, &src_ip_1, &src_ip_2, &src_ip_3, &src_ip_mask,
            &dst_ip_0, &dst_ip_1, &dst_ip_2, &dst_ip_3, &dst_ip_mask,
            &src_port_begin, &src_port_end, &dst_port_begin, &dst_port_end,
            &proto, &proto_mask) != 16) {
            fprintf(stderr, "Illegal rule format\n");
            exit(-1);
        }

        /* src ip */
        src_ip = ((src_ip_0 & 0xff) << 24) | ((src_ip_1 & 0xff) << 16) |
            ((src_ip_2 & 0xff) << 8) | (src_ip_3 & 0xff);
        src_ip_mask = src_ip_mask > 32 ? 32 : src_ip_mask;
        src_ip_mask = (uint32_t)(~((1ULL << (32 - src_ip_mask)) - 1));
        rs->rules[i].dim[DIM_SIP][0].u32 = src_ip & src_ip_mask;
        rs->rules[i].dim[DIM_SIP][1].u32 = src_ip | (~src_ip_mask);

        /* dst ip */
        dst_ip = ((dst_ip_0 & 0xff) << 24) | ((dst_ip_1 & 0xff) << 16) |
            ((dst_ip_2 & 0xff) << 8) | (dst_ip_3 & 0xff);
        dst_ip_mask = dst_ip_mask > 32 ? 32 : dst_ip_mask;
        dst_ip_mask = (uint32_t)(~((1ULL << (32 - dst_ip_mask)) - 1));
        rs->rules[i].dim[DIM_DIP][0].u32 = dst_ip & dst_ip_mask;
        rs->rules[i].dim[DIM_DIP][1].u32 = dst_ip | (~dst_ip_mask);

        /* src port */
        rs->rules[i].dim[DIM_SPORT][0].u16 = src_port_begin & 0xffff;
        rs->rules[i].dim[DIM_SPORT][1].u16 = src_port_end & 0xffff;
        if (rs->rules[i].dim[DIM_SPORT][0].u16 >
                rs->rules[i].dim[DIM_SPORT][1].u16) {
            swap(rs->rules[i].dim[DIM_SPORT][0].u16,
                    rs->rules[i].dim[DIM_SPORT][1].u16);
        }

        /* dst port */
        rs->rules[i].dim[DIM_DPORT][0].u16 = dst_port_begin & 0xffff;
        rs->rules[i].dim[DIM_DPORT][1].u16 = dst_port_end & 0xffff;
        if (rs->rules[i].dim[DIM_DPORT][0].u16 >
                rs->rules[i].dim[DIM_DPORT][1].u16) {
            swap(rs->rules[i].dim[DIM_DPORT][0].u16,
                    rs->rules[i].dim[DIM_DPORT][1].u16);
        }

        /* proto */
        if (proto_mask == 0xff) {
            rs->rules[i].dim[DIM_PROTO][0].u8 = proto & 0xff;
            rs->rules[i].dim[DIM_PROTO][1].u8 = proto & 0xff;
        } else if (proto_mask == 0) {
            rs->rules[i].dim[DIM_PROTO][0].u8 = 0;
            rs->rules[i].dim[DIM_PROTO][1].u8 = 0xff;
        } else {
            fprintf(stderr, "Protocol mask error: %02x\n", proto_mask);
            exit(-1);
        }

        rs->rules[i].pri = i;

        rs->num++;
        i++;
    }

    fclose(rule_fp);

    printf("%d rules loaded\n", rs->num);

    return;
}

void unload_rules(struct rule_set *rs)
{
    free(rs->rules);
    return;
}

void load_trace(struct trace *t, const char *tf)
{
    FILE *trace_fp;
    unsigned int i = 0;

    printf("Loading trace from %s\n", tf);

    if ((trace_fp = fopen(tf, "r")) == NULL) {
        fprintf(stderr, "Cannot open file %s", tf);
        exit(-1);
    }

    t->pkts = calloc(PKT_MAX, sizeof(struct packet));
    if (t->pkts == NULL) {
        perror("Cannot allocate memory for packets");
        exit(-1);
    }
    t->num = 0;

    while (!feof(trace_fp)) {
        if (i >= PKT_MAX) {
            fprintf(stderr, "Too many packets\n");
            exit(-1);
        }

        if (fscanf(trace_fp, PKT_FMT,
            &t->pkts[i].val[DIM_SIP].u32, &t->pkts[i].val[DIM_DIP].u32,
            &t->pkts[i].val[DIM_SPORT].u32, &t->pkts[i].val[DIM_DPORT].u32,
            &t->pkts[i].val[DIM_PROTO].u32, &t->pkts[i].match) != 6) {
            fprintf(stderr, "Illegal packet format\n");
            exit(-1);
        }

        t->pkts[i].val[DIM_SPORT].u16 = t->pkts[i].val[DIM_SPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_DPORT].u16 = t->pkts[i].val[DIM_DPORT].u32 & 0xffff;
        t->pkts[i].val[DIM_PROTO].u8 = t->pkts[i].val[DIM_PROTO].u32 & 0xff;
        t->pkts[i].match--; //rule priority start @ 0

        t->num++;
        i++;
    }

    fclose(trace_fp);

    printf("%d packets loaded\n", t->num);

    return;
}

void unload_trace(struct trace *t)
{
    free(t->pkts);
    return;
}

int is_equal(union point *left, union point *right)
{
    return left->u128.high == right->u128.high
        && left->u128.low == right->u128.low;
}

int is_less(union point *left, union point *right)
{
    return left->u128.high < right->u128.high ||
        (left->u128.high == right->u128.high &&
         left->u128.low < right->u128.low);
}

int is_less_equal(union point *left, union point *right)
{
    return is_less(left, right) || is_equal(left, right);
}

int is_greater(union point *left, union point *right)
{
    return left->u128.high > right->u128.high ||
        (left->u128.high == right->u128.high &&
         left->u128.low > right->u128.low);
}

int is_greater_equal(union point *left, union point *right)
{
    return is_greater(left, right) || is_equal(left, right);
}

void point_inc(union point *point)
{
    point->u128.low++;

    if (point->u128.low == 0) {
        point->u128.high++;
    }

    return;
}

void point_dec(union point *point)
{
    point->u128.low--;

    if (point->u128.low == -1) {
        point->u128.high--;
    }

    return;
}

void point_not(union point *out, union point *point)
{
    out->u128.high = ~point->u128.high;
    out->u128.low = ~point->u128.low;
    return;
}

void point_and(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high & right->u128.high;
    out->u128.low = left->u128.low & right->u128.low;
    return;
}

void point_or(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high | right->u128.high;
    out->u128.low = left->u128.low | right->u128.low;
    return;
}

void point_xor(union point *out, union point *left, union point *right)
{
    out->u128.high = left->u128.high ^ right->u128.high;
    out->u128.low = left->u128.low ^ right->u128.low;
    return;
}

void point_xnor(union point *out, union point *left, union point *right)
{
    out->u128.high = ~(left->u128.high ^ right->u128.high);
    out->u128.low = ~(left->u128.low ^ right->u128.low);
    return;
}

void point_print(union point *point)
{
    printf("%016llx%016llx\n", point->u128.high, point->u128.low);
}

void set_bit(union point *p, unsigned int bit, unsigned int val)
{
    if (bit < 64) {
        if (val != 0) {
            p->u128.low |= 1ULL << (bit - 64);
        } else {
            p->u128.low &= ~(1ULL << (bit - 64));
        }
    } else {
        if (val != 0) {
            p->u128.high |= 1ULL << (bit - 64);
        } else {
            p->u128.high &= ~(1ULL << (bit - 64));
        }
    }

    return;
}

void gen_prefix_mask(union point *p, unsigned int bits,
        unsigned int mask_len)
{
    if (mask_len == 0) {
        p->u128.high = 0;
        p->u128.low = 0;
    } else if (mask_len <= 64) {
        if (bits < 64) {
            p->u128.high = 0;
            p->u128.low = ~((1ULL << (bits - mask_len)) - 1)
                & ((1ULL << bits) - 1);
        } else if (bits == 64) {
            p->u128.high = 0;
            p->u128.low = ~((1ULL << (64 - mask_len)) - 1);
        } else {
            p->u128.high = ~((1ULL << (64 - mask_len)) - 1);
            p->u128.low = 0;
        }
    } else {
        p->u128.high = -1;
        p->u128.low = ~((1ULL << (128 - mask_len)) - 1);
    }

    return;
}

void gen_suffix_mask(union point *p, unsigned int mask_len)
{
    if (mask_len < 64) {
        p->u128.high = 0;
        p->u128.low = (1ULL << mask_len) - 1;
    } else if (mask_len == 64) {
        p->u128.high = 0;
        p->u128.low = - 1;
    } else if (mask_len < 128) {
        p->u128.high = (1ULL << (mask_len - 64)) - 1;
        p->u128.low = -1;
    } else {
        p->u128.high = -1;
        p->u128.low = - 1;
    }

    return;
}

void range2prefix(struct prefix_head *head, struct range *range,
        unsigned int bits)
{
    union point broad, high, tmp0;
    struct prefix_node *pn;
    struct queue_node *node, *node1;
    struct queue_head queue = STAILQ_HEAD_INITIALIZER(queue);

    STAILQ_INIT(head);

    node = calloc(1, sizeof(*node));
    if (node == NULL) {
        perror("out of memory\n");
        exit(-1);
    }

    node->r = *range;
    node->p.value.u128.high = 0;
    node->p.value.u128.low = 0;
    node->p.prefix_len = 0;

    STAILQ_INSERT_HEAD(&queue, node, n);

    /* I hate recursive function */
    while (!STAILQ_EMPTY(&queue)) {
        node = STAILQ_FIRST(&queue);
        STAILQ_REMOVE_HEAD(&queue, n);

        gen_suffix_mask(&tmp0, bits - node->p.prefix_len);
        point_or(&broad, &node->p.value, &tmp0);

        if (is_equal(&node->r.begin, &node->p.value) &&
            is_equal(&node->r.end, &broad)) {

            pn = calloc(1, sizeof(*pn));
            if (pn == NULL) {
                perror("out of memory\n");
                exit(-1);
            }

            pn->p = node->p;
            STAILQ_INSERT_TAIL(head, pn, n);
            free(node);
            continue;
        }

        node->p.prefix_len++;

        high = node->p.value;
        set_bit(&high, bits - node->p.prefix_len, 1);

        /*
         * binary cut: case A
         *                       !
         * node range     |----| !
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        if (is_less(&node->r.end, &high)) {
            STAILQ_INSERT_HEAD(&queue, node, n);

        /*
         * binary cut: case B
         *                       !
         * node range            |----|
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        } else if (is_greater_equal(&node->r.begin, &high)) {
            node->p.value = high;
            STAILQ_INSERT_HEAD(&queue, node, n);

        /*
         * binary cut: case C
         *                       !
         * node range         |--!--|
         *                       !
         * prefix range |--------!--------|
         *                       !
         */
        } else {
            node1 = calloc(1, sizeof(*node1));
            if (node1 == NULL) {
                perror("out of memory\n");
                exit(-1);
            }

            /* left part */
            node1->r.begin = node->r.begin;
            gen_suffix_mask(&tmp0, bits - node->p.prefix_len);
            point_or(&node1->r.end, &node->p.value, &tmp0);
            node1->p.value = node->p.value;
            node1->p.prefix_len = node->p.prefix_len;

            /* right part */
            node->r.begin = high;
            node->p.value = high;

            STAILQ_INSERT_HEAD(&queue, node, n);
            STAILQ_INSERT_HEAD(&queue, node1, n);
        }
    }

    return;
}

void prefix2range(struct range *range, struct prefix *prefix,
        unsigned int bits)
{
    union point point;

    gen_prefix_mask(&point, bits, prefix->prefix_len);
    point_and(&range->begin, &prefix->value, &point);

    gen_suffix_mask(&point, bits - prefix->prefix_len);
    point_or(&range->end, &prefix->value, &point);

    return;
}

void split_range_rule(struct rule_head *head, struct rule *rule)
{
    int i;
    struct rule_node *node;
    struct prefix_node *prfx_node;
    struct prefix_head prfx_head[DIM_MAX];
    struct prefix_node *prfx_cur[DIM_MAX] = {0};
    unsigned int bits[DIM_MAX] = {32, 32, 16, 16, 8};

    bzero(prfx_head, sizeof(prfx_head));
    STAILQ_INIT(head);

    /* range2prefix on each dimension INDEPENDENTLY */
    for (i = 0; i < DIM_MAX; i++) {
        range2prefix(&prfx_head[i], (struct range *)&rule->dim[i], bits[i]);
        prfx_cur[i] = STAILQ_FIRST(&prfx_head[i]);
    }

    /* CROSS PRODUCT all dimensions */
    while (1) {
        node = calloc(1, sizeof(*node));
        if (node == NULL) {
            perror("out of memory\n");
            exit(-1);
        }

        for (i = 0; i < DIM_MAX; i++) {
            prefix2range((struct range *)&node->r.dim[i],
                    &prfx_cur[i]->p, bits[i]);
        }

        node->r.pri = rule->pri;

        STAILQ_INSERT_TAIL(head, node, n);

        /* calculate the carry from the last dimension */
        prfx_cur[DIM_PROTO] = STAILQ_NEXT(prfx_cur[DIM_PROTO], n);

        for (i = DIM_PROTO; i > DIM_INV; i--) {
            if (prfx_cur[i] != NULL) {
                continue;
            }

            /* the first dimension is overflow */
            if (i == DIM_SIP) {
                goto done;
            }

            /* carry forward */
            prfx_cur[i - 1] = STAILQ_NEXT(prfx_cur[i - 1], n);
            prfx_cur[i] = STAILQ_FIRST(&prfx_head[i]);
        }
    }

done:
    for (i = 0; i < DIM_MAX; i++) {
        while (!STAILQ_EMPTY(&prfx_head[i])) {
            prfx_node = STAILQ_FIRST(&prfx_head[i]);
            STAILQ_REMOVE_HEAD(&prfx_head[i], n);
            free(prfx_node);
        }
    }

    return;
}

