/*
 *     Filename: pc_eval.h
 *  Description: Header file for packet classification evaluation
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

#ifndef __PC_EVAL_H__
#define __PC_EVAL_H__

#include <stdint.h>
#include <sys/queue.h>
#include <sys/time.h>

#define RULE_MAX (1 << 17)  /* 128K */
#define PKT_MAX (1 << 17)   /* 128K */

#define CACHE_LINE_SIZE 64 /* 64 bytes */

#define ALIGN(size, align) ({ \
        const typeof(align) __align = align; \
        ((size) + (__align - 1)) & ~(__align - 1);})

/* compatible with classbench from wustl */
#define RULE_FMT "@%u.%u.%u.%u/%u %u.%u.%u.%u/%u %u : %u %u : %u %x/%x\n"
#define PKT_FMT "%u %u %u %u %u %d\n"

enum {
    DIM_INV = -1,
    DIM_SIP = 0,
    DIM_DIP = 1,
    DIM_SPORT = 2,
    DIM_DPORT = 3,
    DIM_PROTO = 4,
    DIM_MAX = 5
};

enum {
    METHOD_INV = -1,
    METHOD_HS = 0,
};

/* little endian */
union point {
    struct { uint64_t low, high; } u128;
    uint64_t u64;
    uint32_t u32;
    uint16_t u16;
    uint8_t u8;
};

/* range rule, compatible with struct range */
struct rule {
    union point dim[DIM_MAX][2]; //[2] means range
    int pri;
};

struct rule_node {
    struct rule r;
    STAILQ_ENTRY(rule_node) n;
};

STAILQ_HEAD(rule_head, rule_node);

struct rule_set {
    struct rule *rules; //rule_set_array_ptr
    int num;
};


struct packet {
    union point val[DIM_MAX];
    int match; //match the rule's row num
};

struct trace {
    struct packet *pkts; //pts_array_ptr
    int num;
};

struct range {
    union point begin;
    union point end;
};

struct range_node {
    struct range r;
    STAILQ_ENTRY(range_node) n;
};

STAILQ_HEAD(range_head, range_node);

struct prefix {
    union point value;
    int prefix_len;
};

struct prefix_node {
    struct prefix p;
    STAILQ_ENTRY(prefix_node) n;
};

STAILQ_HEAD(prefix_head, prefix_node);

uint64_t make_timediff(struct timeval *start, struct timeval *stop);

void load_rules(struct rule_set *rs, const char *rf);
void unload_rules(struct rule_set *rs);

void load_trace(struct trace *t, const char *tf);
void unload_trace(struct trace *t);

int is_equal(union point *left, union point *right);
int is_less(union point *left, union point *right);
int is_less_equal(union point *left, union point *right);
int is_greater(union point *left, union point *right);
int is_greater_equal(union point *left, union point *right);

void point_inc(union point *point);
void point_dec(union point *point);
void point_not(union point *out, union point *point);
void point_and(union point *out, union point *left, union point *right);
void point_or(union point *out, union point *left, union point *right);
void point_xor(union point *out, union point *left, union point *right);
void point_xnor(union point *out, union point *left, union point *right);
void point_print(union point *point);

void set_bit(union point *p, unsigned int bit, unsigned int val);

void gen_prefix_mask(union point *p, unsigned int bits,
        unsigned int mask_len);
void gen_suffix_mask(union point *p, unsigned int mask_len);

void range2prefix(struct prefix_head *head, struct range *range,
        unsigned int bits);
void prefix2range(struct range *range, struct prefix *prefix,
        unsigned int bits);

void split_range_rule(struct rule_head *head, struct rule *rule);

#endif /* __PC_EVAL_H__ */

