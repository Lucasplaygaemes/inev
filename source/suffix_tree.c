/*
 * suffix_tree.c - High-Performance Arena-Allocated Suffix Tree
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "suffix_tree.h"

typedef struct Edge Edge;
typedef struct Node {
    Edge* edges_head;
    struct Node* suffix_link;
} Node;

struct Edge {
    unsigned char label;
    int start;
    int* end;
    Node* child;
    Edge* next;
};

struct SuffixTree {
    const char* text;
    size_t text_len;
    Node* root;
    int* global_end;
    
    Node* active_node;
    int active_edge_idx;
    int active_length;
    int remaining;

    // Arena Allocation (Zero Fragmentation, Zero Memory Leaks)
    void** blocks;
    int block_count;
    int block_capacity;
    size_t current_block_offset;
};

#define BLOCK_SIZE (1024 * 1024 * 16) // 16MB blocks

void* tree_alloc(SuffixTree* tree, size_t size) {
    size = (size + 7) & ~7; // Alinha para 8 bytes
    if (tree->block_count == 0 || tree->current_block_offset + size > BLOCK_SIZE) {
        if (tree->block_count >= tree->block_capacity) {
            tree->block_capacity = tree->block_capacity == 0 ? 16 : tree->block_capacity * 2;
            tree->blocks = realloc(tree->blocks, tree->block_capacity * sizeof(void*));
        }
        void* new_block = malloc(BLOCK_SIZE);
        if (!new_block) return NULL;
        tree->blocks[tree->block_count++] = new_block;
        tree->current_block_offset = 0;
    }
    void* ptr = (char*)tree->blocks[tree->block_count - 1] + tree->current_block_offset;
    tree->current_block_offset += size;
    return ptr;
}

Node* create_node(SuffixTree* tree) {
    Node* node = (Node*)tree_alloc(tree, sizeof(Node));
    if (node) {
        node->edges_head = NULL;
        node->suffix_link = NULL;
    }
    return node;
}

Edge* create_edge(SuffixTree* tree, unsigned char label, int start, int* end, Node* child) {
    Edge* edge = (Edge*)tree_alloc(tree, sizeof(Edge));
    if (edge) {
        edge->label = label;
        edge->start = start;
        edge->end = end;
        edge->child = child;
        edge->next = NULL;
    }
    return edge;
}

Edge* find_edge(Node* node, unsigned char label) {
    if (!node) return NULL;
    Edge* e = node->edges_head;
    while (e) {
        if (e->label == label) return e;
        e = e->next;
    }
    return NULL;
}

void add_edge(Node* node, Edge* edge) {
    if (!node || !edge) return;
    edge->next = node->edges_head;
    node->edges_head = edge;
}

int edge_length(Edge* e, int pos) {
    return *(e->end) == -1 ? (pos + 1 - e->start) : (*(e->end) - e->start + 1);
}

void extend(SuffixTree* tree, int pos) {
    tree->remaining++;
    Node* last_new_node = NULL;

    while (tree->remaining > 0) {
        if (tree->active_length == 0) tree->active_edge_idx = pos;

        if (!tree->active_node) tree->active_node = tree->root;

        unsigned char active_label = (unsigned char)tree->text[tree->active_edge_idx];
        Edge* active_edge = find_edge(tree->active_node, active_label);

        if (active_edge == NULL) {
            Node* next = create_node(tree);
            if (!next) return;
            Edge* new_e = create_edge(tree, active_label, pos, tree->global_end, next);
            add_edge(tree->active_node, new_e);

            if (last_new_node != NULL) {
                last_new_node->suffix_link = tree->active_node;
                last_new_node = NULL;
            }
        } else {
            int len = edge_length(active_edge, pos);
            if (tree->active_length >= len) {
                tree->active_node = active_edge->child;
                tree->active_edge_idx += len;
                tree->active_length -= len;
                continue;
            }
            if (tree->text[active_edge->start + tree->active_length] == tree->text[pos]) {
                tree->active_length++;
                if (last_new_node != NULL) last_new_node->suffix_link = tree->active_node;
                break;
            }

            int* split_end = (int*)tree_alloc(tree, sizeof(int));
            if (!split_end) return;
            *split_end = active_edge->start + tree->active_length - 1;
            
            Node* new_node = create_node(tree);
            if (!new_node) return;

            Edge* new_edge = create_edge(tree, (unsigned char)tree->text[pos], pos, tree->global_end, create_node(tree));
            add_edge(new_node, new_edge);

            active_edge->child->suffix_link = tree->root;
            
            Edge* split_edge = create_edge(tree, (unsigned char)tree->text[*split_end + 1], *split_end + 1, active_edge->end, active_edge->child);
            add_edge(new_node, split_edge);
            
            active_edge->end = split_end;
            active_edge->child = new_node;

            if (last_new_node != NULL) last_new_node->suffix_link = new_node;
            last_new_node = new_node;
        }

        tree->remaining--;
        if (tree->active_node == tree->root && tree->active_length > 0) {
            tree->active_length--;
            tree->active_edge_idx = pos - tree->remaining + 1;
        } else if (tree->active_node != tree->root) {
            tree->active_node = tree->active_node->suffix_link ? tree->active_node->suffix_link : tree->root;
        }
    }
}

SuffixTree* st_create(const char* text, size_t len) {
    if (len == 0) return NULL;
    SuffixTree* tree = (SuffixTree*)malloc(sizeof(SuffixTree));
    if (!tree) return NULL;
    memset(tree, 0, sizeof(SuffixTree));

    tree->text = text;
    tree->text_len = len;
    
    tree->global_end = (int*)tree_alloc(tree, sizeof(int));
    *tree->global_end = -1;
    
    tree->root = create_node(tree);
    tree->root->suffix_link = tree->root;
    
    tree->active_node = tree->root;
    tree->active_length = 0;
    tree->active_edge_idx = -1;
    tree->remaining = 0;

    for (int i = 0; i < (int)len; i++) {
        (*tree->global_end)++;
        extend(tree, i);
    }
    return tree;
}

int st_find_longest_match(SuffixTree* tree, const char* query, size_t query_len) {
    if (!tree || !tree->root) return 0;
    Node* current_node = tree->root;
    int match_len = 0;
    for (size_t i = 0; i < query_len; ) {
        Edge* edge = find_edge(current_node, (unsigned char)query[i]);
        if (edge == NULL) break;

        int edge_len = edge_length(edge, (int)tree->text_len - 1);
        for (int j = 0; j < edge_len && i < query_len; j++, i++, match_len++) {
            if (query[i] != tree->text[edge->start + j]) {
                return match_len;
            }
        }
        current_node = edge->child;
        if (!current_node) break;
    }
    return match_len;
}

void st_free(SuffixTree* tree) {
    if (!tree) return;
    // Arena destruction: Instantaneous and 100% leak-free!
    for (int i = 0; i < tree->block_count; i++) {
        free(tree->blocks[i]);
    }
    free(tree->blocks);
    free(tree);
}
