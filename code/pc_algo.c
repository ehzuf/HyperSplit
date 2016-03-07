/*
 *     Filename: pc_algo.c
 *  Description: Source file for packet classification algorithm
 *
 *       Author: Yaxuan Qi (yaxuan@tsinghua.edu.cn)
 *               Xiang Wang (xiang.wang.s@gmail.com)
 *               Xiaohe Hu (huxioahe10@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pc_algo.h"

struct seg_point {
    union point pnt;
    struct { uint8_t begin :1; uint8_t end :1; } flag;
};

struct node_queue_entry {
    struct hs_bd_node *bd_node;
    int offset;
    STAILQ_ENTRY(node_queue_entry) e;
};

STAILQ_HEAD(node_queue_head, node_queue_entry);

static struct {
    size_t segment_num[DIM_MAX];
    size_t segment_total;

    size_t worst_depth;
    size_t average_depth;

    size_t tree_node_num;
    size_t leaf_node_num;

    /* TODO: assume max_depth = 128 */
    size_t depth_node[128][2];
} g_statistics;

static int seg_pnt_cmp(const void *a, const void *b)
{
    struct seg_point *pa = (typeof(pa))a;
    struct seg_point *pb = (typeof(pb))b;

    if (is_less(&pa->pnt, &pb->pnt)) {
        return -1;
    } else if (is_greater(&pa->pnt, &pb->pnt)) {
        return 1;
    } else {
        return 0;
    }
}

static int build_hs_tree(const struct rule_set *rs,
        struct hs_bd_node *cur_node, int depth)
{
    int *wght, wght_all;
    float wght_avg, wght_jdg;
    int max_pnt, num, pnt_num, d2s, d, i, j;

    union point thresh;
    struct rule_set child_rs;
    struct seg_point *seg_pnts;
    struct range lrange, rrange;

    max_pnt = d2s = 0;
    num = rs->num << 1;
    wght_avg = rs->num + 1; //max, all rules project one segment

    bzero(&lrange, sizeof(lrange));
    bzero(&rrange, sizeof(rrange));

    wght = malloc(num * sizeof(*wght));
    seg_pnts  = malloc(num * sizeof(*seg_pnts));
    child_rs.rules = malloc(rs->num * sizeof(*child_rs.rules));
    if (wght == NULL || seg_pnts == NULL || child_rs.rules == NULL) {
        free(wght);
        free(seg_pnts);
        free(child_rs.rules);
        return -1;
    }

    /*
     * start here
     */
    for (d = 0; d < DIM_MAX; d++) {
        bzero(wght, num * sizeof(*wght));
        bzero(seg_pnts, num * sizeof(*seg_pnts));

        /*
         * shadow rules on each dim
         */
        for (i = 0; i < num; i += 2) {
            seg_pnts[i].pnt = rs->rules[i >> 1].dim[d][0];
            seg_pnts[i].flag.begin = 1;
            seg_pnts[i + 1].pnt = rs->rules[i >> 1].dim[d][1];
            seg_pnts[i + 1].flag.end = 1;
        }

        qsort(seg_pnts, num, sizeof(*seg_pnts), seg_pnt_cmp);

        /*
         * make segments. Note: pnts with the same val may form one seg
         *                Deal with the same val condition
         *                Compact the seg_pnts
         */
        for (pnt_num = 0, i = pnt_num + 1; i < num; i++) {
            //for loop used to scan two indexes
            //pnt_num increases conditionally, i increases directly
            //pnt_num increases in the loops according to some condition
            //i increases every loop
            if (is_equal(&seg_pnts[pnt_num].pnt, &seg_pnts[i].pnt)) {
                seg_pnts[pnt_num].flag.begin |= seg_pnts[i].flag.begin;
                seg_pnts[pnt_num].flag.end |= seg_pnts[i].flag.end;

                if (i + 1 != num) {
                    //when i is not the end, go to the next loop
                    //pnt_num doesn't increase
                    continue;
                }

                if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                    seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                    seg_pnts[pnt_num++].flag.end = 0;
                    seg_pnts[pnt_num].flag.begin = 0;
                }

                break;
            }

            //the following statements only work
            //when seg_pnts[pnt_num] is unequal to seg_pnts[i] or i == num-1
            //when the former if is true, this if is true possibly
            if (seg_pnts[pnt_num].flag.begin & seg_pnts[pnt_num].flag.end) {
                seg_pnts[pnt_num + 1] = seg_pnts[pnt_num];
                seg_pnts[pnt_num++].flag.end = 0;
                seg_pnts[pnt_num].flag.begin = 0;
            }

            seg_pnts[++pnt_num] = seg_pnts[i];
        }

        if (++pnt_num > max_pnt) {
            max_pnt = pnt_num;
        }

        if (depth == 0) {
            g_statistics.segment_num[d] = pnt_num;
            g_statistics.segment_total *= pnt_num;
        }

        if (pnt_num < 3) {
            continue; /* skip this dim: no more ranges */
        }

        /*
         * gen heuristic info
         */
        for (wght_all = 0, i = 0; i < pnt_num - 1; i++) {
            for (wght[i] = 0, j = 0; j < rs->num; j++) {
                if (is_less_equal(&rs->rules[j].dim[d][0],
                        &seg_pnts[i].pnt) &&
                    is_greater_equal(&rs->rules[j].dim[d][1],
                        &seg_pnts[i + 1].pnt)) {
                    wght[i]++;
                    wght_all++;
                }
            }
        }

        wght_jdg = (float)wght_all / (pnt_num - 1);

        if (wght_avg <= wght_jdg) {
            continue; /* skip this dim: the less the better */
        }

        /*
         * found dimension candidate
         */
        d2s = d, wght_avg = wght_jdg;

        for (wght_jdg = wght[0], i = 1; i < pnt_num - 1;
            wght_jdg += wght[i], i++) {

            thresh = seg_pnts[i].pnt;
            if (seg_pnts[i].flag.begin) {
                point_dec(&thresh);
            }

            if (wght_jdg > (wght_all / 2.f)) {
                break; /* reach the half of the wght */
            }
        }

        lrange.begin = seg_pnts[0].pnt;
        lrange.end = thresh;

        rrange.begin = thresh;
        point_inc(&rrange.begin);
        rrange.end = seg_pnts[pnt_num - 1].pnt;

    } /* end of for (d = 0; d < DIM_MAX; d++) */

    free(seg_pnts);
    free(wght);

    /*
     * gen leaf node
     */
    if (max_pnt < 3) {
        cur_node->d2s = -1;
        cur_node->depth = depth;
        cur_node->thresh.u64 = rs->rules[0].pri;
        cur_node->child[0] = NULL;
        cur_node->child[1] = NULL;

        free(child_rs.rules);
        g_statistics.leaf_node_num++;
        g_statistics.depth_node[depth][1]++;
        g_statistics.average_depth += depth;
        if (g_statistics.worst_depth < depth) {
            g_statistics.worst_depth = depth;
        }
        return 0;
    }

    cur_node->d2s = d2s;
    cur_node->depth = depth;
    cur_node->thresh = thresh;

    /*
     * gen left child
     */
    cur_node->child[0] = malloc(sizeof(*cur_node->child[0]));
    if (cur_node->child[0] == NULL) {
        free(child_rs.rules);
        return -1;
    }

    bzero(child_rs.rules, rs->num * sizeof(*child_rs.rules));

    for (i = 0, child_rs.num = 0; i < rs->num; i++) {
        if (is_greater(&rs->rules[i].dim[d2s][0], &lrange.end) ||
            is_less(&rs->rules[i].dim[d2s][1], &lrange.begin)) {
            continue;
        }

        child_rs.rules[child_rs.num] = rs->rules[i];

        /* rules must be trimmed */
        if (is_less(&child_rs.rules[child_rs.num].dim[d2s][0],
            &lrange.begin)) {
            child_rs.rules[child_rs.num].dim[d2s][0] = lrange.begin;
        }
        if (is_greater(&child_rs.rules[child_rs.num].dim[d2s][1],
            &lrange.end)) {
            child_rs.rules[child_rs.num].dim[d2s][1] = lrange.end;
        }

        child_rs.num++;
    }

    if (build_hs_tree(&child_rs, cur_node->child[0], depth + 1) != 0) {
        free(cur_node->child[0]);
        free(child_rs.rules);
        return -1;
    }

    /*
     * gen right child
     */
    cur_node->child[1] = malloc(sizeof(*cur_node->child[1]));
    if (cur_node->child[1] == NULL) {
        free(child_rs.rules);
        return -1;
    }

    bzero(child_rs.rules, rs->num * sizeof(*child_rs.rules));

    for (i = 0, child_rs.num = 0; i < rs->num; i++) {
        if (is_greater(&rs->rules[i].dim[d2s][0], &rrange.end) ||
            is_less(&rs->rules[i].dim[d2s][1], &rrange.begin)) {
            continue;
        }

        child_rs.rules[child_rs.num] = rs->rules[i];

        /* rules must be trimmed */
        if (is_less(&child_rs.rules[child_rs.num].dim[d2s][0],
            &rrange.begin)) {
            child_rs.rules[child_rs.num].dim[d2s][0] = rrange.begin;
        }
        if (is_greater(&child_rs.rules[child_rs.num].dim[d2s][1],
            &rrange.end)) {
            child_rs.rules[child_rs.num].dim[d2s][1] = rrange.end;
        }

        child_rs.num++;
    }

    if (build_hs_tree(&child_rs, cur_node->child[1], depth + 1) != 0) {
        free(cur_node->child[1]);
        free(child_rs.rules);
        return -1;
    }

    free(child_rs.rules);
    g_statistics.tree_node_num++;
    g_statistics.depth_node[depth][0]++;
    return 0;
}

static void cleanup_hs_tree(struct hs_bd_node *node)
{
    if (node->child[0] == NULL && node->child[1] == NULL) {
        return;
    }

    cleanup_hs_tree(node->child[0]);
    free(node->child[0]);

    cleanup_hs_tree(node->child[1]);
    free(node->child[1]);

    return;
}

static void cleanup_bd(void *userdata)
{
    struct hs_bd_node *root = *(typeof(root) *)userdata;

    cleanup_hs_tree(root);
    free(root);

    return;
}

static int hs_gather(void *rt_data, void *bd_data)
{
    struct hs_bd_node *bd_node = *(typeof(bd_node) *)bd_data;
    union hs_rt_node *rt_root = NULL;
    union hs_rt_node *rt_node = NULL;
    struct hs_rt *rt = malloc(sizeof(*rt));
    struct node_queue_head *p_nqh = malloc(sizeof(*p_nqh));
    struct node_queue_entry *p_nqe;
    int node_num = g_statistics.tree_node_num + g_statistics.leaf_node_num;
    void *base = malloc(node_num * sizeof(*rt_node) + CACHE_LINE_SIZE);
    int mem_num = 0, i;

    if (base == NULL || p_nqh == NULL || rt == NULL) {
        fprintf(stderr, "malloc rt_data mem or p_nqh or rt fails!\n");
        return -1;
    }

    /*
     * malloc for root rt_node
     */
    rt_root = (typeof(rt_node))ALIGN((size_t)base, CACHE_LINE_SIZE);
    rt_node = rt_root;
    mem_num++;

    /*
     * trigger queue
     */
    STAILQ_INIT(p_nqh);
    p_nqe = malloc(sizeof(*p_nqe));
    if (p_nqe == NULL) {
        fprintf(stderr, "malloc p_nqe fails!\n");
        goto err;
    }
    p_nqe->offset = 0;
    p_nqe->bd_node = bd_node;
    STAILQ_INSERT_TAIL(p_nqh, p_nqe, e);

    /*
     * process
     */
    while (!STAILQ_EMPTY(p_nqh)) {
        if (mem_num > node_num) {
            fprintf(stderr, "rt mem overflow!\n");
            goto err;
        }

        /*
         * pop queue element, find corresponding addr
         */
        p_nqe = STAILQ_FIRST(p_nqh);
        STAILQ_REMOVE_HEAD(p_nqh, e);
        bd_node = p_nqe->bd_node;
        rt_node = rt_root + p_nqe->offset;
        free(p_nqe);

        if (bd_node->child[0] != NULL) {
            /*
             * update node data
             */
            rt_node->u64 = 0;
            rt_node->node.intr = 1;
            rt_node->node.d2s = bd_node->d2s;
            rt_node->node.thresh = bd_node->thresh.u32;
            /*
             * malloc new addr for rt_node, push element
             */
            rt_node->node.child = mem_num;
            mem_num += 2;
            for (i = 0; i < 2; i++) {
                p_nqe = malloc(sizeof(*p_nqe));
                if (p_nqe == NULL) {
                    fprintf(stderr, "malloc p_nqe fails\n");
                    goto err;
                }
                p_nqe->offset = mem_num - 2 + i;
                p_nqe->bd_node = bd_node->child[i];
                STAILQ_INSERT_TAIL(p_nqh, p_nqe, e);
            }
        } else {
            rt_node->u64 = 0;
            rt_node->node.thresh = bd_node->thresh.u32;
        }
    }

    if (mem_num != node_num) {
        fprintf(stderr, "mem_num != node_num\n");
        goto err;
    } else {
        fprintf(stderr, "mem alloc: %dKB\n",\
                (mem_num * sizeof(*rt_node) + CACHE_LINE_SIZE) >> 10);
    }

    cleanup_bd(bd_data);
    rt->root = rt_root;
    rt->base = base;
    *(typeof(rt) *)rt_data = rt;
    return 0;

err:
    while (!STAILQ_EMPTY(p_nqh)) {
        p_nqe = STAILQ_FIRST(p_nqh);
        STAILQ_REMOVE_HEAD(p_nqh, e);
        free(p_nqe);
    }
    free(p_nqh);
    free(base);
    free(rt);
    *(typeof(rt) *)rt_data = NULL;
    return -1;
}

int build(const struct rule_set *rs, void *userdata)
{
    int i;
    struct hs_bd_node *bd_root = calloc(1, sizeof(*bd_root));

    if (bd_root == NULL) {
        return -1;
    }

    g_statistics.segment_total = 1;

    if (build_hs_tree(rs, bd_root, 0) == 0) {
        /* rule_set statistics */
        printf("\nsegment_num = ");
        for (i = 0; i < DIM_MAX; i++) {
            printf("%lu ", g_statistics.segment_num[i]);
        }
        printf("\nsegment_total = %lu", g_statistics.segment_total);

        /* depth statistics */
        printf("\nworst_depth = %lu", g_statistics.worst_depth);
        printf("\naverage_depth = %f", (float)g_statistics.average_depth /
                g_statistics.leaf_node_num);

        /* node statistics */
        printf("\ntree_node_num = %lu", g_statistics.tree_node_num);
        printf("\nleaf_node_num = %lu", g_statistics.leaf_node_num);
        printf("\ntotal_memory = %lu", (g_statistics.tree_node_num +
            g_statistics.leaf_node_num) << 3);

        /* node statistics detail */
        printf("\ndepth   node    intrnl  leaf\n");
        for (i = 0; i <= g_statistics.worst_depth; i++) {
            printf("%-8d%-8d%-8d%-8d\n", i, g_statistics.depth_node[i][0] +
                g_statistics.depth_node[i][1], g_statistics.depth_node[i][0],
                g_statistics.depth_node[i][1]);
        }
        printf("\n");

        if (hs_gather(userdata, &bd_root) == 0) {
            return 0;
        } else {
            cleanup_bd(&bd_root);
            return -1;
        }
    } else {
        *(struct hs_rt **)userdata = NULL;
        return -1;
    }
}

int search(const struct trace *t, const void *userdata)
{
    int i, c;

    for (i = 0; i < t->num; i++) {
        if ((c = classify(&t->pkts[i], userdata)) != t->pkts[i].match) {
            fprintf(stderr, "pkt[%d] match:%d, classify: %d", i+1, t->pkts[i].match+1, c+1);
            return -1;
        }
    }

    return 0;
}

int classify(struct packet *pkt, const void *userdata)
{
    struct hs_rt *rt = *(typeof(rt) *)userdata;
    union hs_rt_node *rt_node = rt->root;

    while (rt_node->node.intr) {
        if (pkt->val[rt_node->node.d2s].u32 <= rt_node->node.thresh) {
            rt_node = rt->root + rt_node->node.child;
        } else {
            rt_node = rt->root + rt_node->node.child + 1;
        }
    }

    return rt_node->node.thresh;
}

void cleanup(void *userdata)
{
    struct hs_rt *rt = *(typeof(rt) *)userdata;
    free(rt->base);
    free(rt);

    return;
}
