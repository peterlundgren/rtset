const char *usage_text =
"rtset file\n"
"\n"
"Configure real-time priorities with a centralized configuration file.\n"
"\n"
"  file  Path to config file. If '-', read from stdin.\n";

#define _GNU_SOURCE
#include <dirent.h>
#include <inttypes.h>
#include <regex.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/sched.h>

#define MAX_LINE_LENGHT 1000
#define MAX_SECTION_LENGHT 100
#define MAX_PARAMETER_LENGHT 100
#define MAX_VALUE_LENGHT 1000
#define MAX_RULES_COLUMNS 10

static void usage()
{
	printf("%s", usage_text);
}

struct section_testfoo {
	char *testbar;
};

enum parameter_policy_action {
	CONFIG_POLICY_LEAVE_ALONE,
	CONFIG_POLICY_SET
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
	regex_t regex;
	enum parameter_policy_action policy_action;
	int policy;
	enum parameter_priority_action priority_action;
	unsigned int rt_priority;
	enum parameter_affinity_action affinity_action;
	uint64_t affinity;
	cpu_set_t cpuset;
};

struct section_rules {
	struct config_rule *list;
};

struct config {
	struct section_testfoo testfoo;
	struct section_rules rules;
};

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
	void (*set_value)(struct config *, struct config_file *);
};

struct process_list {
	struct process_list *next;
	pid_t pid;
	pid_t tid;
	unsigned int policy;
	unsigned int rt_priority;
	char comm[16];
};

static int is_lower_alpha(char c)
{
	return 'a' <= c && c <= 'z';
}

static int is_int(char c)
{
	return '0' <= c && c <= '9';
}

static void pdie(const char *s)
{
	perror(s);
	exit(EXIT_FAILURE);
}

static void die(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void *malloc_or_die(size_t size)
{
	void *p = malloc(size);

	if (!p)
		die("Out of memory\n");

	return p;
}

static struct config *alloc_config()
{
	struct config *config = malloc_or_die(sizeof(struct config));

	return config;
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

static struct process_list *alloc_process_list()
{
	struct process_list *ps = malloc_or_die(sizeof(struct process_list));

	memset(ps, 0, sizeof(struct process_list));

	return ps;
}

static int open_config_file(struct config_file *cf, char *filename)
{
	if (strcmp(filename, "-") == 0) {
		cf->f = stdin;
		cf->filename = "<stdin>";
	} else {
		cf->f = fopen(filename, "r");
	}
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
	cr->policy_action = CONFIG_POLICY_LEAVE_ALONE;
	cr->policy = SCHED_NORMAL;
	cr->priority_action = CONFIG_PRIORITY_LEAVE_ALONE;
	cr->rt_priority = 0;
	cr->affinity_action = CONFIG_AFFINITY_LEAVE_ALONE;
	cr->affinity = -1;
	CPU_ZERO(&cr->cpuset);

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
	exit(EXIT_FAILURE);
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
		(*leading)++;

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

static void set_testfoo_testbar_value(struct config *config, struct config_file *cf)
{
	config->testfoo.testbar = strdup(cf->value);
}

static int set_testfoo_parameter(struct config_file *cf)
{
	char *parameter = cf->parameter;

	if (strcmp(parameter, "testbar") == 0) {
		cf->set_value = set_testfoo_testbar_value;
	} else {
		return 0;
	}
	return 1;
}

static int set_section(struct config_file *cf)
{
	char *section = cf->section;

	if (strcmp(section, "testfoo") == 0) {
		cf->set_parameter = set_testfoo_parameter;
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

static void parse_value(struct config *config, struct config_file *cf)
{
	int c, i, comment = 0;

	for (i = 0; i < MAX_VALUE_LENGHT; i++) {
		c = get_next_char(cf);
		if (c == EOF || c == '\n') {
			cf->value[i] = '\0';
			trim(cf->value);
			cf->set_value(config, cf);
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

static void parse_parameter(struct config *config, struct config_file *cf)
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
			parse_value(config, cf);
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
	char errbuf[1000];
	int len, err;

	len = strlen(pattern);
	rule->pattern = malloc_or_die(len + 2);
	rule->pattern[0] = '^';
	memcpy(&rule->pattern[1], pattern, len);
	rule->pattern[len + 1] = '$';
	err = regcomp(&rule->regex, rule->pattern, REG_EXTENDED);
	if (err) {
		regerror(err, &rule->regex, errbuf, 1000);
		parse_error(cf, "Could not compile regex: %s\n", errbuf);
	}
}

static void parse_policy(struct config_file *cf, struct config_rule *rule, char *policy)
{
	if (strcmp(policy, "*") == 0)
		rule->policy_action = CONFIG_POLICY_LEAVE_ALONE;
	else if (strcmp(policy, "NORMAL") == 0)
		rule->policy = SCHED_NORMAL;
	else if (strcmp(policy, "OTHER") == 0)
		rule->policy = SCHED_NORMAL;
	else if (strcmp(policy, "FIFO") == 0)
		rule->policy = SCHED_FIFO;
	else if (strcmp(policy, "RR") == 0)
		rule->policy = SCHED_RR;
	else if (strcmp(policy, "BATCH") == 0)
		rule->policy = SCHED_BATCH;
	else
		parse_error(cf, "Unrecognized scheduling policy\n");
	rule->policy_action = CONFIG_POLICY_SET;
}

static void parse_priority(struct config_file *cf, struct config_rule *rule, char *rt_priority)
{
	if (strcmp(rt_priority, "*") == 0)
		rule->priority_action = CONFIG_PRIORITY_LEAVE_ALONE;
	else {
		rule->priority_action = CONFIG_PRIORITY_SET;
		rule->rt_priority = atoi(rt_priority);
		if (rule->rt_priority < 1 || rule->rt_priority > 99)
			parse_error(cf, "Priority must be between 1 and 99 inclusive\n");
	}
}

static void parse_affinity(struct config_file *cf, struct config_rule *rule, char *affinity)
{
	uint64_t bit;
	int i;

	if (strcmp(affinity, "*") == 0)
		rule->affinity_action = CONFIG_AFFINITY_LEAVE_ALONE;
	else {
		rule->affinity_action = CONFIG_AFFINITY_SET;
		rule->affinity = strtol(affinity, NULL, 0);
		if (strncmp(affinity, "0x", 2) == 0) {
			for (bit = 1, i = 0; bit; bit <<= 1, i++)
				if (bit & rule->affinity)
					CPU_SET(i, &rule->cpuset);
		} else if (is_int(affinity[0])) {
			CPU_SET(rule->affinity, &rule->cpuset);
		} else {
			parse_error(cf, "Affinity must be decimal or hexidecimal\n");
		}
	}
}

static void (*get_column_parser(struct config_file *cf, char *column))(struct config_file *, struct config_rule *, char *)
{
	if (strcmp(column, "pattern") == 0)
		return parse_pattern;
	if (strcmp(column, "policy") == 0)
		return parse_policy;
	if (strcmp(column, "rtprio") == 0)
		return parse_priority;
	if (strcmp(column, "affinity") == 0)
		return parse_affinity;
	parse_error(cf, "Unrecognized column name '%s'\n", column);
	return NULL;
}

static void parse_rules(struct config *config, struct config_file *cf)
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
				if (header)
					parse_col[column] = get_column_parser(cf, buf);
				if (rule) {
					if (column == 0) {
						prev_cr = cr;
						cr = alloc_config_rule();
						if (prev_cr)
							prev_cr->next = cr;
						else
							config->rules.list = cr;
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

static void parse_config(struct config *config, struct config_file *cf)
{
	int c;
	int comment = 0, rules = 0; // TODO bool

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
				parse_rules(config, cf);
			else
				parse_parameter(config, cf);
			continue;
		}
		parse_error(cf, "Unexpected character '%c'\n", c);
	}
}

/* Requires Linux 2.5.19 */
static struct process_list *parse_stat(pid_t the_pid, pid_t the_tid)
{
	int ppid, pgrp, session, tty_nr, tpgid, exit_signal, processor;
	unsigned int flags, rt_priority, policy;
	unsigned long int minflt, cminflt, majflt, cmajflt, utime, stime,
			vsize, rsslim, startcode, endcode, startstack, kstkesp,
			kstkeip, signal, blocked, sigignore, sigcatch, wchan,
			nswap, cnswap;
	long int cutime, cstime, priority, nice, num_threads, itrealvalue, rss;
	unsigned long long int starttime;
	char comm[16];
	char state;

	char path[1024];
	FILE *f;
	int len;
	char c;
	int is_comm = 0;
	int i = 0;
	struct process_list *ps;

	len = snprintf(path, sizeof(path)-1, "/proc/%d/task/%d/stat", the_pid, the_tid);
	path[len] = 0;
	f = fopen(path, "r");
	if (!f)
		return NULL;

	while ((c = fgetc(f))) {
		if (c == '(') {
			is_comm = 1;
		} else if (c == ')' || i > 15) {
			comm[i] = '\0';
			break;
		} else if (is_comm) {
			comm[i++] = c;
		}
	}

	fscanf(f, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %u %u ", &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime, &cstime, &priority, &nice, &num_threads, &itrealvalue, &starttime, &vsize, &rss, &rsslim, &startcode, &endcode, &startstack, &kstkesp, &kstkeip, &signal, &blocked, &sigignore, &sigcatch, &wchan, &nswap, &cnswap, &exit_signal, &processor, &rt_priority, &policy);
	fclose(f);

	ps = alloc_process_list();
	ps->pid = the_pid;
	ps->tid = the_tid;
	ps->policy = policy;
	ps->rt_priority = rt_priority;
	memcpy(ps->comm, comm, sizeof(ps->comm));

	return ps;
}

static struct process_list *get_ps()
{
	DIR *proc_dir, *task_dir;
	struct dirent *proc_dirent, *task_dirent;
	pid_t pid;
	pid_t tid;
	char path[1024];
	int len;
	struct process_list *ps_head = NULL, *ps_prev = NULL, *ps;

	proc_dir = opendir("/proc/");
	if (!proc_dir)
		pdie("Could not open /proc/");

	while ((proc_dirent = readdir(proc_dir)) != NULL) {
		if (proc_dirent->d_type != DT_DIR)
			continue;
		if (!is_int(proc_dirent->d_name[0]))
			continue;

		pid = atoi(proc_dirent->d_name);
		len = snprintf(path, sizeof(path)-1, "/proc/%s/task", proc_dirent->d_name);
		path[len] = 0;
		task_dir = opendir(path);
		if (!task_dir) {
			continue;
		}

		while ((task_dirent = readdir(task_dir)) != NULL) {
			if (task_dirent->d_type != DT_DIR)
				continue;
			if (!is_int(task_dirent->d_name[0]))
				continue;

			tid = atoi(task_dirent->d_name);
			ps = parse_stat(pid, tid);
			if (!ps)
				continue;
			if (!ps_head)
				ps_head = ps;
			if (ps_prev)
				ps_prev->next = ps;
			ps_prev = ps;
		}
		closedir(task_dir);
	}
	closedir(proc_dir);

	return ps_head;
}

static void apply_rule(struct config_rule *rule, struct process_list *ps)
{
	int policy;
	unsigned int rt_priority;
	struct sched_param param;

	if (rule->policy_action == CONFIG_POLICY_SET)
		policy = rule->policy;
	else
		policy = ps->policy;

	if (rule->priority_action == CONFIG_PRIORITY_SET)
		rt_priority = rule->rt_priority;
	else
		rt_priority = ps->rt_priority;

	if (rule->policy_action == CONFIG_PRIORITY_SET ||
	    rule->priority_action == CONFIG_PRIORITY_SET) {
		param.sched_priority = rt_priority;
		sched_setscheduler(ps->tid, policy, &param);
	}

	if (rule->affinity_action == CONFIG_AFFINITY_SET)
		sched_setaffinity(ps->tid, sizeof(cpu_set_t), &rule->cpuset);
}

static void apply_config(struct config *config, struct process_list *ps)
{
	struct config_rule *rule;
	int err;

	while (ps) {
		rule = config->rules.list;
		while (rule != NULL) {
			err = regexec(&rule->regex, ps->comm, 0, NULL, 0);
			if (!err)
				apply_rule(rule, ps);

			rule = rule->next;
		}
		ps = ps->next;
	}
}

int main(int argc, char *argv[])
{
	struct config *config = alloc_config();
	struct config_file *cf = alloc_config_file();
	struct process_list *ps;
	char *filename;
	int err = 0;

	if (argc != 2) {
		usage();
		exit(EXIT_FAILURE);
	}

	filename = argv[1];
	err = open_config_file(cf, filename);
	if (err)
		pdie("Could not open config file");

	parse_config(config, cf);
	ps = get_ps();
	apply_config(config, ps);

	close_config_file(cf);

	return err;
}
