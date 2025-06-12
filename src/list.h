#pragma once

#include <stdlib.h>
#include <stdbool.h>

// forward list (singly-linked)
typedef struct flist_node {
    struct flist_node *next;
} s_flist_node;

// list (doubly-linked)
// TODO: add functions
typedef struct list_node {
    s_flist_node _list;
    struct list_node *prev;
} s_list_node;

typedef void (*f_list_node_del)(s_flist_node *node);
typedef bool (*f_list_node_cmp)(const s_flist_node *a, const s_flist_node *b);

void flist_push_front(s_flist_node **list, s_flist_node *node);
void flist_pop_front(s_flist_node **list, f_list_node_del func);
void flist_push_back(s_flist_node **list, s_flist_node *node);
void flist_pop_back(s_flist_node **list, f_list_node_del func);
void flist_clear(s_flist_node **list, f_list_node_del func);
size_t flist_size(s_flist_node *const *list);
void flist_sort(s_flist_node **list, f_list_node_cmp func);
