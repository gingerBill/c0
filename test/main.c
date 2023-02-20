#include <stdio.h> // fgetc, stdin
#include <ctype.h> // isspace
#include <stdlib.h> // malloc

// Simple calculator language
//
// expression: literal
//           | expression '*' expression
//           | expression '/' expression
//           | expression '+' expression
//           | expression '/' expression
//           | '(' expression ')'
//           ;
//
// literal:  TOKEN_LIT
//           ;

//
// Lexer
//
typedef struct Token Token;
typedef struct Lexer Lexer;

typedef enum TokenKind TokenKind;

enum TokenKind {
	TOKEN_EOF, TOKEN_PLUS, TOKEN_MINUS, TOKEN_STAR, TOKEN_SLASH, TOKEN_LIT,
	TOKEN_LPAREN, TOKEN_RPAREN,
};

struct Token {
	TokenKind kind;
	int literal;
};

static Token token(TokenKind kind) {
	Token result;
	result.kind = kind;
	return result;
}

static Token literal(int literal) {
	Token result;
	result.kind = TOKEN_LIT;
	result.literal = literal;
	return result;
}

struct Lexer {
	FILE *file;
	int line;
	int unget;
};

void lexer_unget(Lexer *lexer, int ch) {
	lexer->unget = ch;
}

int lexer_next(Lexer *lexer) {
	if (lexer->unget) {
		int ch = lexer->unget;
		lexer->unget = 0;
		return ch;
	}
	int ch = fgetc(lexer->file);
	if (ch == '\n') {
		lexer->line++;
	}
	return ch;
}

int lexer_skip(Lexer *lexer) {
	int ch = lexer_next(lexer);
	while (isspace(ch)) ch = lexer_next(lexer);
	return ch;
}

int lexer_scan_literal(Lexer *lexer, int ch) {
	int value = 0;
	while (isdigit(ch)) {
		value = value * 10 + (ch - '0');
		ch = lexer_next(lexer);
	}
	lexer_unget(lexer, ch);
	return value;
}

Token lexer_scan(Lexer *lexer) {
	int ch = lexer_skip(lexer);
	switch (ch) {
	case EOF: return token(TOKEN_EOF);
	case '+': return token(TOKEN_PLUS);
	case '-': return token(TOKEN_MINUS);
	case '*': return token(TOKEN_STAR);
	case '/': return token(TOKEN_SLASH);
	case '(': return token(TOKEN_LPAREN);
	case ')': return token(TOKEN_RPAREN);
	default:
		if (isdigit(ch)) {
			return literal(lexer_scan_literal(lexer, ch));
		}
	}
	return token(TOKEN_EOF);
}

//
// Parser
//
typedef struct Node Node;
typedef struct Parser Parser;

typedef enum NodeKind NodeKind;

enum NodeKind {
	NODE_UNK, NODE_ADD, NODE_SUB, NODE_MUL, NODE_DIV, NODE_LIT,
};

struct Node {
	NodeKind op;
	Node *left;
	Node *right;
	int literal;
};

struct Parser {
	Lexer lexer;
	Token token;
};

Node *node(int op, Node *left, Node *right, int literal) {
	Node *result = malloc(sizeof *result);
	result->op = op;
	result->left = left;
	result->right = right;
	result->literal = literal;
	return result;
}

Node *leaf(int op, int literal) {
	return node(op, 0, 0, literal);
}

Node *unary(int op, Node *left, int literal) {
	return node(op, left, 0, literal);
}

NodeKind arith(TokenKind kind) {
	switch (kind) {
	case TOKEN_PLUS:
		return NODE_ADD;
	case TOKEN_MINUS:
		return NODE_SUB;
	case TOKEN_STAR:
		return NODE_MUL;
	case TOKEN_SLASH:
		return NODE_DIV;
	default:
		return NODE_UNK;
	}
}

Node *binary(Parser *parser, int p_prec);

Node *primary(Parser *parser) {
	Node *node = 0;
	switch (parser->token.kind) {
	case TOKEN_LIT:
		node = leaf(NODE_LIT, parser->token.literal);
		parser->token = lexer_scan(&parser->lexer);
		return node;
	case TOKEN_LPAREN:
		parser->token = lexer_scan(&parser->lexer); // Skip '('
		node = binary(parser, 0);
		parser->token = lexer_scan(&parser->lexer); // Expected ')'
		return node;
	default:
		return 0;
	}
}

int prec(TokenKind kind) {
	switch (kind) {
	case TOKEN_EOF:
	case TOKEN_LIT:
		return 0;
	case TOKEN_PLUS:
	case TOKEN_MINUS:
		return 1;
	case TOKEN_STAR:
	case TOKEN_SLASH:
		return 2;
	}
	return -1;
}

Node *binary(Parser *parser, int p_prec) {
	Node *left = primary(parser);
	TokenKind kind = parser->token.kind;
	if (kind == TOKEN_EOF) {
		return left;
	}
	while (prec(kind) > p_prec) {
		parser->token = lexer_scan(&parser->lexer);
		Node *right = binary(parser, prec(kind));
		left = node(arith(kind), left, right, 0);
		kind = parser->token.kind;
		if (kind == TOKEN_EOF) {
			return left;
		}
	}
	return left;
}

Node *parse(const char *file) {
	Parser parser;
	parser.lexer.file = fopen(file, "r");
	parser.lexer.unget = 0;
	parser.token = lexer_scan(&parser.lexer);
	return binary(&parser, 0);
}

void dump(Node *node) {
	if (!node) return;
	switch (node->op) {
	case NODE_UNK:
		return;
	case NODE_LIT:
		printf("%d", node->literal);
		return;
	case NODE_ADD:
		printf("(+ ");
		break;
	case NODE_SUB:
		printf("(- ");
		break;
	case NODE_MUL:
		printf("(* ");
		break;
	case NODE_DIV:
		printf("(/ ");
		break;
	}
	dump(node->left);
	printf(" ");
	dump(node->right);
	printf(")");
}

#include "../lib/c0.h" // ir builder
#include "../lib/c0_backend.h" // c0_emit
#include "../lib/c0_context.h" // c0_context
#include "../lib/c0_allocator.h"

C0Instr *walk(C0Proc *p, Node *node) {
	if (!node) return 0;
	C0Instr *left = 0;
	C0Instr *right = 0;
	if (node->left) left = walk(p, node->left);
	if (node->right) right = walk(p, node->right);
	switch (node->op) {
	case NODE_ADD:
		return c0_push_bin(p, C0Instr_add_u32, C0Basic_i32, left, right);
	case NODE_SUB:
		return c0_push_bin(p, C0Instr_sub_u32, C0Basic_i32, left, right);
	case NODE_MUL:
		return c0_push_bin(p, C0Instr_mul_u32, C0Basic_i32, left, right);
	case NODE_DIV:
		return c0_push_bin(p, C0Instr_quo_u32, C0Basic_i32, left, right);
	case NODE_LIT:
		return c0_push_basic_i32(p, node->literal);
	case NODE_UNK:
		return 0;
	}
	return 0;
}

int main(int argc, char **argv) {
	argc--;
	argv++;

	if (argc == 0) return 1;

	c0_context = C0_DEFAULT_CONTEXT;

	const C0Allocator arena = c0_arena_create(&C0_STDLIB_ALLOCATOR);

	c0_context.allocator = &arena;

	Node *tree = parse("test.calc");
	C0Gen gen;
	c0_gen_init(&gen);

	C0AggType *agg_i32 = c0_agg_type_basic(&gen, C0Basic_i32);
	C0AggType *agg_void = c0_agg_type_basic(&gen, C0Basic_void);
	C0Proc *p = c0_proc_create(&gen, C0_SLIT("main"), c0_agg_type_proc(&gen, agg_i32, 0, 0, 0));

	C0Instr *r = walk(p, tree);

	C0Array(C0AggType*) agg_types = 0;
	c0_array_push(agg_types, agg_i32);

	C0Proc *xx = c0_proc_create(&gen, C0_SLIT("print"), c0_agg_type_proc(&gen, agg_void, 0, agg_types, 0));
	C0Instr *x = c0_push_call_proc1(p, xx, r);
	c0_push_return(p, r);
	c0_proc_finish(p);

	if (!strcmp(argv[0], "--asm")) {
		C0Array(u8) data = c0_emit(&gen, C0_SLIT("ASM"));
		c0_array_push(data, 0);
		printf("%s\n", data);
	} else if (!strcmp(argv[0], "--c")) {
		C0Array(u8) data = c0_emit(&gen, C0_SLIT("C"));
		c0_array_push(data, 0);
		printf("%s\n", data);
	} else if (!strcmp(argv[0], "--ast")) {
		dump(tree);
		printf("\n");
	}

	c0_arena_destroy(&arena);
}