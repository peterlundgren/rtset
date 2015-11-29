#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGHT 1000
#define MAX_SECTION_LENGHT 100
#define MAX_PARAMETER_LENGHT 100
#define MAX_VALUE_LENGHT 100

const char *usage_text =
"rtset file\n";

static void usage()
{
	printf("%s", usage_text);
}

static int is_lower_alpha(char c)
{
	return 'a' <= c && c <= 'z';
}

struct config_file {
	FILE *f;
	char *filename;
	int line_number;
	int column_number;
	int newline;
	char c;
	char line[MAX_LINE_LENGHT];
	char section[MAX_SECTION_LENGHT];
	char parameter[MAX_SECTION_LENGHT];
	char value[MAX_VALUE_LENGHT];
};

static void die(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	exit(1);
}

static void *malloc_or_die(size_t size)
{
	void *p = malloc(size);

	if (!p)
		die("Out of memory\n");

	return p;
}

static struct config_file *alloc_config_file()
{
	struct config_file *cf = malloc_or_die(sizeof(struct config_file));

	cf->f = NULL;
	cf->line_number = 0;
	cf->column_number = 0;
	cf->newline = 0;
	cf->line[0] = '\0';
	cf->section[0] = '\0';

	return cf;
}

static int open_config_file(struct config_file *cf, char *filename)
{
	cf->f = fopen(filename, "r");
	if (cf->f) {
		cf->filename = strdup(filename);
		cf->line_number = 1;
		cf->column_number = 0;
		cf->newline = 0;

		return 1;
	}

	return 0;
}

static void close_config_file(struct config_file *cf)
{
	fclose(cf->f);
}

static void vparse_error_at(struct config_file *cf, int line_number,
                            int column_number, const char* format, va_list ap)
{
	int c;

	fprintf(stderr, "%s:%d:%d: error: ",
	         cf->filename, line_number, column_number);
	vfprintf(stderr, format, ap);
	fprintf(stderr, " %s", cf->line);
	if (!cf->newline) {
		for (;;) {
			c = fgetc(cf->f);
			if (c == EOF || c == '\n')
				break;
			fputc(c, stderr);
		}
		fputc('\n', stderr);
	}
	fprintf(stderr, "%*c^\n", column_number, ' ');
	exit(1);
}

static void parse_error_at(struct config_file *cf, int line_number,
                           int column_number, const char* format, ...)
{
	va_list ap;

	va_start(ap, format);
	vparse_error_at(cf, line_number, column_number, format, ap);
	va_end(ap);
}

static void parse_error(struct config_file *cf, const char* format, ...)
{
	va_list ap;

	va_start(ap, format);
	vparse_error_at(cf, cf->line_number, cf->column_number, format, ap);
	va_end(ap);
}

static int get_next_char(struct config_file *cf)
{
	if (cf->newline) {
		cf->line_number++;
		cf->column_number = 0;
		cf->newline = 0;
	}
	cf->c = fgetc(cf->f);
	cf->line[cf->column_number] = cf->c;
	cf->line[cf->column_number + 1] = '\0';
	cf->column_number++;
	if (cf->c == '\n') {
		cf->newline = 1;
	} else if (cf->column_number >= MAX_LINE_LENGHT - 1) {
		parse_error(cf, "Line exceeded max length %d\n", MAX_LINE_LENGHT - 1);
	}

	return cf->c;
}

static void parse_section(struct config_file *cf)
{
	int c, i;
	int line_number = cf->line_number;
	int column_number = cf->column_number;

	for (i = 0; i < MAX_SECTION_LENGHT; i++) {
		c = get_next_char(cf);
		if (c == EOF)
			parse_error(cf, "Unexpected end of file\n");
		if (c == '\n')
			parse_error(cf, "Unexpected newline\n");
		if (c == ']') {
			cf->section[i] = '\0';
			printf("Section: %s\n", cf->section);
			return;
		}
		if (!is_lower_alpha(c))
			parse_error(cf, "Section names must contain only [a-z]\n");
		cf->section[i] = c;
	}
	parse_error(cf, "Section name exceeded max length %d\n",
	            MAX_SECTION_LENGHT - 1);
}

static void parse_expect(struct config_file *cf, char expect)
{
	int c, i;

	for (i = 0;; i++) {
		if (i == 0)
			c = cf->c;
		else
			c = get_next_char(cf);
		if (c == ' ')
			continue;
		if (c == '=')
			return;
		parse_error(cf, "Expecting '%c'\n", expect);
	}
}

static void parse_value(struct config_file *cf)
{
	int c, i;
	int line_number = cf->line_number;
	int column_number = cf->column_number;

	for (i = 0; i < MAX_VALUE_LENGHT; i++) {
		c = get_next_char(cf);
		if (c == EOF || c == '\n') {
			cf->value[i] = '\0';
			printf("Value: %s\n", cf->value);
			return;
		}
		cf->value[i] = c;
	}
	parse_error(cf, "Value exceeded max length %d\n",
	            MAX_VALUE_LENGHT - 1);
}

static void parse_parameter(struct config_file *cf)
{
	int c, i;
	int line_number = cf->line_number;
	int column_number = cf->column_number;

	for (i = 0; i < MAX_PARAMETER_LENGHT; i++) {
		if (i == 0)
			c = cf->c;
		else
			c = get_next_char(cf);
		if (c == EOF)
			parse_error(cf, "Unexpected end of file\n");
		if (c == '\n')
			parse_error(cf, "Unexpected newline\n");
		if (c == ' ' || c == '=') {
			cf->parameter[i] = '\0';
			printf("Parameter: %s\n", cf->parameter);
			parse_expect(cf, '=');
			parse_value(cf);
			return;
		}
		if (!is_lower_alpha(c))
			parse_error(cf, "Parameter names must contain only [a-z]\n");
		cf->parameter[i] = c;
	}
	parse_error(cf, "Parameter name exceeded max length %d\n",
	            MAX_SECTION_LENGHT - 1);
}

static int parse_config(struct config_file *cf)
{
	int c;
	int comment = 0;

	for (;;) {
		c = get_next_char(cf);
		if (c == EOF)
			break;
		if (c == '\n') {
			comment = 0;
			continue;
		}
		if (comment)
			continue;
		if (c == ' ')
			continue;
		if (c == '#') {
			comment = 1;
			continue;
		}
		if (c == '[') {
			parse_section(cf);
			continue;
		}
		if (is_lower_alpha(c)) {
			if (cf->section[0] == '\0')
				parse_error(cf, "Expected section before "
				            "parameter definition\n");
			parse_parameter(cf);
		}
	}
}

int main(int argc, void *argv[])
{
	struct config_file *cf = alloc_config_file();
	int ret = -1;
	char *filename;

	if (argc < 2) {
		die("No file specified\n");
	}
	if (argc > 2) {
		die("Too many arguments\n");
	}
	filename = argv[1];

	if (open_config_file(cf, filename)) {
		ret = parse_config(cf);
		close_config_file(cf);
	}

	return 0;
}
