const char *usage_text =
"get-config config pid [tid]\n"
"\n"
"  config  policy or rt_priority\n"
"  pid     Process id\n"
"  tid     (Optional) Thread id\n";

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/sched.h>

struct process {
	pid_t pid;
	pid_t tid;
	unsigned int policy;
	unsigned int rt_priority;
	char comm[16];
};

static void usage()
{
	printf("%s", usage_text);
}

/* Requires Linux 2.5.19 */
static struct process *parse_stat(pid_t the_pid, pid_t the_tid)
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
	struct process *ps;

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

	ps = malloc(sizeof(struct process));
	ps->pid = the_pid;
	ps->tid = the_tid;
	ps->policy = policy;
	ps->rt_priority = rt_priority;
	memcpy(ps->comm, comm, sizeof(ps->comm));

	return ps;
}

int main(int argc, char *argv[])
{
	struct process *ps;
	pid_t pid, tid;
	char *config;

	if (argc < 3 || argc > 4) {
		usage();
		exit(EXIT_FAILURE);
	}

	config = argv[1];

	pid = atoi(argv[2]);

	if (argc > 3)
		tid = atoi(argv[3]);
	else
		tid = pid;

	ps = parse_stat(pid, tid);

	if (strcmp(config, "policy") == 0) {
		switch (ps->policy) {
		case SCHED_NORMAL:
			printf("OTHER\n");
			break;
		case SCHED_FIFO:
			printf("FIFO\n");
			break;
		case SCHED_RR:
			printf("RR\n");
			break;
		case SCHED_BATCH:
			printf("BATCH\n");
			break;
		}
	} else if (strcmp(config, "rt_priority") == 0) {
		printf("%d\n", ps->rt_priority);
	}
}
