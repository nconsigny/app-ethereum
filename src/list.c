#include "list.h"

void flist_push_front(s_flist_node **list, s_flist_node *node) {
    node->next = *list;
    *list = node;
}

void flist_pop_front(s_flist_node **list, f_list_node_del func) {
    s_flist_node *tmp = *list;

    if (tmp != NULL) {
        *list = tmp->next;
        func(tmp);
    }
}

void flist_push_back(s_flist_node **list, s_flist_node *node) {
    if (*list == NULL) {
        *list = node;
    } else {
        s_flist_node *tmp;
        for (tmp = *list; tmp->next != NULL; tmp = tmp->next)
            ;
        tmp->next = node;
    }
}

void flist_pop_back(s_flist_node **list, f_list_node_del func) {
    s_flist_node *tmp = *list;

    if (tmp != NULL) {
        // only one element
        if (tmp->next == NULL) {
            flist_pop_front(list, func);
        } else {
            for (; tmp->next->next != NULL; tmp = tmp->next)
                ;
            func(tmp->next);
            tmp->next = NULL;
        }
    }
}

void flist_clear(s_flist_node **list, f_list_node_del func) {
    s_flist_node *tmp = *list;
    s_flist_node *next;

    while (tmp != NULL) {
        next = tmp->next;
        if (func) func(tmp);
        tmp = next;
    }
    *list = NULL;
}

size_t flist_size(s_flist_node *const *list) {
    size_t size = 0;

    for (s_flist_node *tmp = *list; tmp != NULL; tmp = tmp->next) size += 1;
    return size;
}

void flist_sort(s_flist_node **list, f_list_node_cmp func) {
    s_flist_node **tmp;
    s_flist_node *a, *b;
    bool sorted;

    do {
        sorted = true;
        for (tmp = list; (*tmp != NULL) && ((*tmp)->next != NULL); tmp = &(*tmp)->next) {
            a = *tmp;
            b = a->next;
            if (func(a, b) == false) {
                *tmp = b;
                a->next = b->next;
                b->next = a;
                sorted = false;
            }
        }
    } while (!sorted);
}
