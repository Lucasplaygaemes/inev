#ifndef SUFFIX_TREE_H
#define SUFFIX_TREE_H

#include <stdlib.h>

// A estrutura opaca da árvore. Os detalhes são escondidos no .c
typedef struct SuffixTree SuffixTree;

// Cria uma árvore de sufixos para um texto de um determinado comprimento.
SuffixTree* st_create(const char* text, size_t len);

// Encontra o comprimento da correspondência mais longa de uma query.
int st_find_longest_match(SuffixTree* tree, const char* query, size_t query_len);

// Encontra a correspondência mais longa e retorna o offset no texto original.
int st_find_match_with_offset(SuffixTree* tree, const char* query, size_t query_len, size_t* out_text_offset);

// Libera a memória da árvore.
void st_free(SuffixTree* tree);

#endif // SUFFIX_TREE_H
