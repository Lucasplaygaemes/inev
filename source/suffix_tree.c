/*
 * suffix_tree.c - Implementação funcional e testada de uma Árvore de Sufixos.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "suffix_tree.h"

// Estruturas internas
typedef struct Node {
    struct Edge* edges[256];
    struct Node* suffix_link;
} Node;

typedef struct Edge {
    int start;
    int* end;
    Node* child;
} Edge;

struct SuffixTree {
    const char* text;
    size_t text_len;
    Node* root;
    int* global_end;
    
    Node* active_node;
    int active_edge_idx;
    int active_length;
    int remaining;
};

// Funções de criação
Node* create_node() {
    Node* node = (Node*)malloc(sizeof(Node));
    memset(node->edges, 0, sizeof(node->edges));
    node->suffix_link = NULL;
    return node;
}

Edge* create_edge(int start, int* end, Node* child) {
    Edge* edge = (Edge*)malloc(sizeof(Edge));
    edge->start = start;
    edge->end = end;
    edge->child = child;
    return edge;
}

int edge_length(Edge* e, int pos) {
    return *(e->end) == -1 ? (pos + 1 - e->start) : (*(e->end) - e->start + 1);
}

// Lógica de extensão de Ukkonen
void extend(SuffixTree* tree, int pos) {
    tree->remaining++;
    Node* last_new_node = NULL;

    while (tree->remaining > 0) {
        if (tree->active_length == 0) tree->active_edge_idx = pos;

        Edge* active_edge = tree->active_node->edges[(unsigned char)tree->text[tree->active_edge_idx]];

        if (active_edge == NULL) {
            tree->active_node->edges[(unsigned char)tree->text[tree->active_edge_idx]] = create_edge(pos, tree->global_end, create_node());
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

            int* split_end = (int*)malloc(sizeof(int));
            *split_end = active_edge->start + tree->active_length - 1;
            Node* new_node = create_node();
            Edge* new_edge = create_edge(pos, tree->global_end, create_node());

            new_node->edges[(unsigned char)tree->text[pos]] = new_edge;
            active_edge->child->suffix_link = tree->root;
            new_node->edges[(unsigned char)tree->text[*split_end + 1]] = create_edge(*split_end + 1, active_edge->end, active_edge->child);
            
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
            tree->active_node = tree->active_node->suffix_link;
        }
    }
}

// API Pública
SuffixTree* st_create(const char* text, size_t len) {
    SuffixTree* tree = (SuffixTree*)malloc(sizeof(SuffixTree));
    tree->text = text;
    tree->text_len = len;
    tree->root = create_node();
    tree->root->suffix_link = tree->root;
    tree->global_end = (int*)malloc(sizeof(int));
    *tree->global_end = -1;
    tree->active_node = tree->root;
    tree->active_length = 0;
    tree->active_edge_idx = -1;
    tree->remaining = 0;

    for (int i = 0; i < len; i++) {
        (*tree->global_end)++;
        extend(tree, i);
    }
    return tree;
}

int st_find_longest_match(SuffixTree* tree, const char* query, size_t query_len) {
    Node* current_node = tree->root;
    int match_len = 0;
    for (size_t i = 0; i < query_len; ) {
        Edge* edge = current_node->edges[(unsigned char)query[i]];
        if (edge == NULL) break;

        int edge_len = edge_length(edge, tree->text_len - 1);
        for (int j = 0; j < edge_len && i < query_len; j++, i++, match_len++) {
            if (query[i] != tree->text[edge->start + j]) {
                return match_len;
            }
        }
        current_node = edge->child;
    }
    return match_len;
}

void free_edges(Node* node) {
    if (!node) return;
    for (int i = 0; i < 256; i++) {
        if (node->edges[i]) {
            free_edges(node->edges[i]->child);
            // A linha abaixo estava causando double free e foi removida.
            // if (*(node->edges[i]->end) != -1) free(node->edges[i]->end);
            free(node->edges[i]);
        }
    }
    free(node);
}

void st_free(SuffixTree* tree) {
    if (!tree) return;
    free_edges(tree->root);
    free(tree->global_end);
    free(tree);
}
