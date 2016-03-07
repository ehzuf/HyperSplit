/*
 *     Filename: pc_algo.h
 *  Description: Header file for packet classification algorithm
 *
 *       Author: Yaxuan Qi (yaxuan@tsinghua.edu.cn)
 *               Xiang Wang (xiang.wang.s@gmail.com)
 *               Xiaohe Hu (huxioahe10@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#ifndef __PC_ALGO_H__
#define __PC_ALGO_H__

#include"pc_eval.h"

#define NODE_NUM_BITS 28;
#define NODE_NUM_MAX (1 << NODE_NUM_BITS)

struct hs_bd_node {
    uint8_t d2s;
    uint8_t depth;
    union point thresh;
    struct hs_bd_node *child[2];
};

union hs_rt_node {
    uint64_t u64;

    struct {
        uint32_t intr :1;
        uint32_t d2s :3;
        uint32_t child :NODE_NUM_BITS;
        uint32_t thresh;
    } node;
};

struct hs_rt {
    union hs_rt_node *root;
    void *base;
};

int build(const struct rule_set *rs, void *userdata);
int search(const struct trace *t, const void *userdata);
int classify(struct packet *pkt, const void *userdata);
void cleanup(void *userdata);

#endif /* __PC_ALGO_H__ */

