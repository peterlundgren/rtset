const char *usage_text =
"test-program threadname\n";

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/prctl.h>

int stop = 0;

static void usage()
{
	printf("%s", usage_text);
}

static void handle_signal(int signal)
{
	switch (signal) {
	case SIGINT:
		stop = 1;
		break;
	default:
		fprintf(stderr, "Unexpected signal %d\n", signal);
		break;
	}
}

int main(int argc, char *argv[])
{
	int err;

	if (argc != 2) {
		usage();
		exit(1);
	}

	if (signal(SIGINT, handle_signal) == SIG_ERR) {
		perror("Could not register signal handler");
		exit(1);
	}

	err = prctl(PR_SET_NAME, argv[1], 0, 0, 0);
	if (err) {
		perror("Could not set thread name");
		exit(1);
	}

	while (!stop) {
		sleep(100);
	}
}
