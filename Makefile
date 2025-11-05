#
# Makefile para o projeto inev
#

# Compilador
CC = gcc

# Flags de compilação:
# -Wall: Ativa todos os avisos (warnings) do compilador.
# -g:    Adiciona informações de debug ao executável.
# -I./source: Informa ao compilador para procurar arquivos de cabeçalho (.h) no diretório 'source'.
CFLAGS = -Wall -g -I./source

# Flags de linkagem:
# -lssl -lcrypto: Linka com as bibliotecas OpenSSL, necessárias para as funções de criptografia.
LDFLAGS = -lssl -lcrypto

# --- Alvos (Targets) ---

# Lista de executáveis que queremos criar.
TARGETS = encoder decoder

# --- Fontes e Objetos ---

# Arquivos fonte (.c) para o encoder.
SRCS_ENCODER = source/encoder.c source/suffix_tree.c
# Gera automaticamente os nomes dos arquivos objeto (.o) a partir dos fontes.
OBJS_ENCODER = $(SRCS_ENCODER:.c=.o)

# Arquivos fonte (.c) para o decoder.
SRCS_DECODER = source/decoder.c
# Gera os nomes dos arquivos objeto (.o).
OBJS_DECODER = $(SRCS_DECODER:.c=.o)

# --- Regras (Rules) ---

# A regra 'all' é a regra padrão, executada quando você digita apenas 'make'.
# Ela depende dos nossos alvos principais.
all: $(TARGETS)

# Regra para criar o executável 'encoder'.
# Depende dos seus arquivos objeto.
encoder: $(OBJS_ENCODER)
	@echo "Linkando o executável: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Regra para criar o executável 'decoder'.
# Depende dos seus arquivos objeto.
decoder: $(OBJS_DECODER)
	@echo "Linkando o executável: $@"
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Regra de padrão para compilar qualquer arquivo .c para .o.
# $< é o primeiro pré-requisito (o arquivo .c).
# $@ é o nome do alvo (o arquivo .o).
# -c: Apenas compila, não linka.
# -MMD: Gera um arquivo de dependência (.d) para os cabeçalhos.
%.o: %.c
	@echo "Compilando: $<"
	$(CC) $(CFLAGS) -c $< -o $@ -MMD

# Regra 'clean' para limpar os arquivos gerados.
# .PHONY diz ao make que 'clean' não é um arquivo.
.PHONY: clean all

clean:
	@echo "Limpando arquivos gerados..."
	rm -f $(TARGETS) $(OBJS_ENCODER) $(OBJS_DECODER) $(SRCS_ENCODER:.c=.d) $(SRCS_DECODER:.c=.d)

# Inclui os arquivos de dependência (.d) gerados.
# Isso faz com que, se um cabeçalho (.h) for modificado, os arquivos .c que o incluem
# sejam recompilados automaticamente. O '-' no início ignora erros se os arquivos não existirem.
-include $(SRCS_ENCODER:.c=.d) $(SRCS_DECODER:.c=.d)