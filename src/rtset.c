#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LINE_LENGHT 1000
#define MAX_SECTION_LENGHT 100
#define MAX_PARAMETER_LENGHT 100
#define MAX_VALUE_LENGHT 1000
#define MAX_RULES_COLUMNS 10

const char *usage_text =
"rtset file\n";

static void usage()
{
	printf("%s", usage_text);
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
	int (*set_parameter)(struct config_file *);
	int (*set_value)(struct config_file *);
};

struct section_foo {
	char *bar;
};

enum parameter_sched {
	CONFIG_SCHED_LEAVE_ALONE,
	CONFIG_SCHED_BATCH,
	CONFIG_SCHED_FIFO,
	CONFIG_SCHED_IDLE,
	CONFIG_SCHED_OTHER,
	CONFIG_SCHED_RR
};

enum parameter_priority_action {
	CONFIG_PRIORITY_LEAVE_ALONE,
	CONFIG_PRIORITY_SET
};

enum parameter_affinity_action {
	CONFIG_AFFINITY_LEAVE_ALONE,
	CONFIG_AFFINITY_SET
};

struct config_rule {
	struct config_rule *next;
	char *pattern;
	enum parameter_sched sched;
	enum parameter_priority_action priority_action;
	int priority;
	enum parameter_affinity_action affinity_action;
	uint64_t affinity;
};

struct section_rules {
	struct config_rule *list;
};

struct config {
	struct section_foo foo;
	struct section_rules rules;
};

struct config rtset_config;

static int is_lower_alpha(char c)
{
	return 'a' <= c && c <= 'z';
}

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

		return 0;
	}

	return -1;
}

static void close_config_file(struct config_file *cf)
{
	fclose(cf->f);
}

static struct config_rule *alloc_config_rule()
{
	struct config_rule *cr = malloc_or_die(sizeof(struct config_rule));

	cr->next = NULL;
	cr->pattern = NULL;
	cr->sched = CONFIG_SCHED_LEAVE_ALONE;
	cr->priority_action = CONFIG_PRIORITY_LEAVE_ALONE;
	cr->priority = 0;
	cr->affinity_action = CONFIG_AFFINITY_LEAVE_ALONE;
	cr->affinity = -1;

	return cr;
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

void trim(char *str)
{
	char *end, *leading = str, *trailing = str;

	/* Trim leading whitespace */
	while(*leading == ' ')
		*leading++;

	/* Copy string in place if there was any leading whitespace */
	if (leading != str) {
		while(*leading != '\0')
			*trailing++ = *leading++;
		*(leading+1) = '\0';
	}

	/* Trim trailing whitespace */
	end = str + strlen(str) - 1;
	while (end > str && *end == ' ')
		end--;
	*(end+1) = '\0';
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

static int set_foo_bar_value(struct config_file *cf)
{
	printf("Bar value: '%s'\n", cf->value);
	rtset_config.foo.bar = strdup(cf->value);
}

static int set_foo_parameter(struct config_file *cf)
{
	char *parameter = cf->parameter;

	printf("Parameter: '%s'\n", cf->parameter);
	if (strcmp(parameter, "bar") == 0) {
		cf->set_value = set_foo_bar_value;
	} else {
		return 0;
	}
	return 1;
}

static int set_section(struct config_file *cf)
{
	char *section = cf->section;

	printf("Section: '%s'\n", cf->section);
	if (strcmp(section, "foo") == 0) {
		cf->set_parameter = set_foo_parameter;
	} else if (strcmp(section, "rules") == 0) {
		cf->set_parameter = NULL;
	} else {
		return 0;
	}

	return 1;
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
			if (!set_section(cf))
				parse_error_at(cf, line_number, column_number,
				               "Unknown section \"%s\"\n",
					       cf->section);
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
	int c, i, comment = 0;
	int line_number = cf->line_number;
	int column_number = cf->column_number;

	for (i = 0; i < MAX_VALUE_LENGHT; i++) {
		c = get_next_char(cf);
		if (c == EOF || c == '\n') {
			cf->value[i] = '\0';
			trim(cf->value);
			cf->set_value(cf);
			return;
		}
		if (comment)
			continue;
		if (c == '#') {
			cf->value[i] = '\0';
			comment = 1;
			continue;
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
			if (!cf->set_parameter(cf))
				parse_error_at(cf, line_number, column_number,
				               "Unknown parameter %s.%s\n",
					       cf->section, cf->parameter);
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

static void parse_pattern(struct config_file *cf, struct config_rule *rule, char *pattern)
{
	rule->pattern = strdup(pattern);
}

static void parse_sched(struct config_file *cf, struct config_rule *rule, char *sched)
{
	if (strcmp(sched, "*") == 0)
		rule->sched = CONFIG_SCHED_LEAVE_ALONE;
	else if (strcmp(sched, "BATCH") == 0)
		rule->sched = CONFIG_SCHED_BATCH;
	else if (strcmp(sched, "FIFO") == 0)
		rule->sched = CONFIG_SCHED_FIFO;
	else if (strcmp(sched, "IDLE") == 0)
		rule->sched = CONFIG_SCHED_IDLE;
	else if (strcmp(sched, "OTHER") == 0)
		rule->sched = CONFIG_SCHED_OTHER;
	else if (strcmp(sched, "RR") == 0)
		rule->sched = CONFIG_SCHED_RR;
	else
		parse_error(cf, "Unrecognized scheduling class\n");
}

static void parse_priority(struct config_file *cf, struct config_rule *rule, char *priority)
{
	if (strcmp(priority, "*") == 0)
		rule->priority_action = CONFIG_PRIORITY_LEAVE_ALONE;
	else {
		rule->priority_action = CONFIG_PRIORITY_SET;
		rule->priority = atoi(priority);
		if (rule->priority < 1 || rule->priority > 99)
			parse_error(cf, "Priority must be between 1 and 99 inclusive\n");
	}
}

static void parse_affinity(struct config_file *cf, struct config_rule *rule, char *affinity)
{
	if (strcmp(affinity, "*") == 0)
		rule->affinity_action = CONFIG_AFFINITY_LEAVE_ALONE;
	else {
		rule->affinity_action = CONFIG_AFFINITY_SET;
		rule->affinity = strtol(affinity, NULL, 0);
	}
}

static void (*get_column_parser(struct config_file *cf, char *column))(struct config_file *, struct config_rule *, char *)
{
	if (strcmp(column, "pattern") == 0)
		return parse_pattern;
	if (strcmp(column, "sched") == 0)
		return parse_sched;
	if (strcmp(column, "priority") == 0)
		return parse_priority;
	if (strcmp(column, "affinity") == 0)
		return parse_affinity;
	parse_error(cf, "Unrecognized column name '%s'\n", column);
}

static void parse_rules(struct config_file *cf)
{
	int c, column = 0, comment = 0, first = 1, i = 0;
	int header = 1, divider = 0, rule = 0;
	char buf[MAX_VALUE_LENGHT];
	void (*parse_col[MAX_RULES_COLUMNS])(struct config_file *, struct config_rule *, char *);
	struct config_rule *cr = NULL, *prev_cr = NULL;

	buf[0] = '\0';
	for (;;) {
		if (first) {
			c = cf->c;
			first = 0;
		} else
			c = get_next_char(cf);
		if (c == '\n')
			comment = 0;
		if (comment)
			continue;
		if (c == ' ' || c == '#' || c == '\n' || c == EOF) {
			if (i != 0) {
				if (header) {
					printf("Header column %d: '%s'\n", column, buf);
					parse_col[column] = get_column_parser(cf, buf);
				}
				if (divider)
					printf("Divider column %d: '%s'\n", column, buf);
				if (rule) {
					printf("Rule column %d: '%s'\n", column, buf);
					if (column == 0) {
						prev_cr = cr;
						cr = alloc_config_rule();
						if (prev_cr)
							prev_cr->next = cr;
						else
							rtset_config.rules.list = cr;
					}
					parse_col[column](cf, cr, buf);
				}
				i = 0;
				buf[0] = '\0';
				column++;
			}
			if (c == '#') {
				comment = 1;
			}
			if (c == '\n') {
				if (header) {
					header = 0;
					divider = 1;
				} else if (divider) {
					divider = 0;
					rule = 1;
				}
				column = 0;
			}
			if (c == EOF)
				return;
			continue;
		}
		buf[i++] = c;
		buf[i] = '\0';
	}
}

static void parse_config(struct config_file *cf)
{
	int c;
	int comment = 0, rules = 0;

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
			if (strcmp(cf->section, "rules") == 0) {
				rules = 1;
			}
			continue;
		}
		if (is_lower_alpha(c)) {
			if (cf->section[0] == '\0')
				parse_error(cf, "Expected section before "
				            "parameter definition\n");
			if (rules)
				parse_rules(cf);
			else
				parse_parameter(cf);
			continue;
		}
		parse_error(cf, "Unexpected character '%c'\n", c);
	}
}

static void do_config()
{
	struct config_rule *rule;
	int i = 0;

	printf("foo.bar = %s\n", rtset_config.foo.bar);
	rule = rtset_config.rules.list;
	while (rule != NULL) {
		printf("Rule %d\n", i);
		printf("  Pattern: %s\n", rule->pattern);
		printf("  Sched: %d\n", rule->sched);
		switch (rule->priority_action) {
		case CONFIG_PRIORITY_LEAVE_ALONE:
			printf("  Priority: Leave alone\n");
			break;
		case CONFIG_PRIORITY_SET:
			printf("  Priority: %d\n", rule->priority);
			break;
		}
		switch (rule->affinity_action) {
		case CONFIG_AFFINITY_LEAVE_ALONE:
			printf("  Affinity: Leave alone\n");
			break;
		case CONFIG_AFFINITY_SET:
			printf("  Affinity: %d\n", rule->affinity);
			break;
		}
		rule = rule->next;
		i++;
	}
}

int main(int argc, void *argv[])
{
	struct config_file *cf = alloc_config_file();
	int err = 0;
	char *filename;

	if (argc < 2) {
		die("No file specified\n");
	}
	if (argc > 2) {
		die("Too many arguments\n");
	}
	filename = argv[1];

	err = open_config_file(cf, filename);
	if (err)
		perror("Could not open config file");

	parse_config(cf);
	do_config();

close_config_file:
	close_config_file(cf);
	return err;
}
