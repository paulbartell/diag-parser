#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <err.h>

#include "diag_input.h"
#include "bit_func.h"
#include "session.h"
#include <stdlib.h>
#include <termios.h>
#include <time.h>

void process_file(char *infile_name, int do_init, time_t max_capture_time);

static void usage(const char *progname, const char *reason)
{
	printf("%s\n", reason);
	printf("Usage: %s [-f <filelist>] [filenames]\n", progname);
	printf("	-g <target>   - Target host for GSMTAP UDP stream\n");
	printf("	-p <pcapfile> - Write to PCAP file\n");
	printf("	-f <filelist> - Read list of input files from <filelist>\n");
	printf("	-i            - Initialize device\n");
	printf("	-v            - Verbose messages\n");
	printf("	-G <seconds>  - Maximum capture time\n");
	printf("	[filenames]   - Read DIAG data from [filenames]\n");
	exit(1);
}

static void chop_newline(char *line)
{
	int newline_pos = strlen(line) - 1;
	if (newline_pos >= 0 && line[newline_pos] == '\n')
	{
		line[newline_pos] = '\0';
	}
}

int main(int argc, char *argv[])
{
	char infile_name[FILENAME_MAX];
	FILE *filelist = NULL;
	char *filelist_name = NULL;
	char *gsmtap_target = NULL;
	char *pcap_target = NULL;
	uint32_t appid = 0;
	int ch;
	long sid = 0;
	long cid = 0;
	int line = 0;
	int init = 0;
	time_t max_capture_time = 0;

	msg_verbose = 0;

	while ((ch = getopt(argc, argv, "p:g:f:viC:G:")) != -1) {
		switch (ch) {
			case 'g':
				gsmtap_target = strdup(optarg);
				break;
			case 'p':
				pcap_target = strdup(optarg);
				break;
			case 'f':
				filelist_name = strdup(optarg);
				break;
			case 'i':
				init = 1;
				break;
			case 'v':
				msg_verbose++;
				break;
			case 'G':
				max_capture_time = strtol(optarg, NULL, 0);
				break;
			case '?':
			default:
				usage(argv[0], "Invalid arguments");
		}
	}

	argc -= optind;
	argv += optind;

	if (filelist_name == NULL && argc == 0)
	{
		errx(1, "Invalid arguments");
	}

	diag_init(sid, cid, gsmtap_target, pcap_target, NULL, appid);

	printf("PARSER_OK\n");
	fflush(stdout);

	//  Handle files passed to command line first
	while (argc > 0)
	{
		process_file(argv[0], init, max_capture_time);
		argc--;
		argv++;
	};

	//  Handle file list
	if (filelist_name)
	{
		filelist = fopen(filelist_name, "rb");
		if (!filelist)
		{
			err(1, "Cannot open file list: %s", filelist_name);
		}

		while (!feof(filelist))
		{
			char *ret = fgets(infile_name, sizeof(infile_name), filelist);
			++line;
			if (ferror(filelist))
			{
				err(1, "Error parsing file list %s:%d", filelist_name, line);
			}
			if (ret) {
				chop_newline(infile_name);
				process_file(infile_name, init, 0);
			}
		}
		fclose(filelist);
	}

	diag_destroy(&sid, &cid);

	return 0;
}

static time_t get_time_monotonic()
{
	struct timespec time;
	clock_gettime(CLOCK_MONOTONIC, &time);
	return time.tv_sec;
}

void process_file(char *infile_name, int do_init, time_t max_capture_time)
{
	uint8_t msg[4096];
	FILE *infile = NULL;
	unsigned len = 0;
	time_t timeout_time = 0;

	if(max_capture_time > 0)
	{
		timeout_time = get_time_monotonic() + max_capture_time;
	}

	if (strcmp(infile_name, "-") == 0)
	{
		infile = stdin;
	}
	else
	{
		infile = fopen(infile_name, "rb+");
		if(!infile)
		{
			warn("File not found: %s", infile_name);
			return;
		}
		int fd = 0;
		fd = fileno(infile);
		if(fd > 0 && isatty(fd) )
		{
			printf("Setting up tty...\n");
			/* Setup termios */
			struct termios tios;
			memset(&tios, 0, sizeof(struct termios));
			errno = 0;
			if (tcgetattr(fd, &tios) == 0)
			{
				tios.c_cflag &= ~(CBAUD | CSIZE | CSTOPB | PARENB | PARODD | CRTSCTS);
				tios.c_iflag &= ~(IGNCR | ICRNL | IUCLC | INPCK | IXON | IXOFF | IXANY );
				tios.c_oflag &= ~(OPOST | OLCUC | OCRNL | ONLCR | ONLRET);
				tios.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHONL);

				tios.c_cc[VMIN] = 1;
				tios.c_cc[VTIME] = 0;
				tios.c_cc[VEOF] = 1;

				/* Ignore parity/framing errors */
				tios.c_iflag |= IGNPAR;

				/* No parity bit, 1 stop bit, 8 data bits */
				tios.c_cflag |= (CS8 | CLOCAL | CREAD);

				cfsetispeed (&tios, B57600);
				cfsetospeed (&tios, B57600);

				if(tcsetattr(fd, TCSANOW, &tios) != 0)
				{
					warn("tcsetattr failed on file %s", infile_name);
				}
			}
			else
			{
				warn("tcgetattr failed on file %s", infile_name);
			}
		}
	}

	if (!infile)
	{
		err(1, "Cannot open input file: %s", infile_name);
	}

	if (do_init)
	{
		diag_start_log(infile);
	}

	diag_set_filename(infile_name);

	for (;;) {
		len = fread_unescape(infile, msg, sizeof(msg));

		if (timeout_time > 0 &&
		    timeout_time <= get_time_monotonic())
		{
			printf("Maximum capture time reached\n");
			fflush(stdout);
			break;
		}

		if(len < 1 && feof(infile))
		{
			printf("Got End of File indication\n");
			break;
		}

		/* Terminate message with standard GSM padding */
		if (len < sizeof(msg) - 1) {
			msg[len] = 0x2b;
		}

		handle_diag(msg, len);
	}

	if (do_init)
	{
		diag_stop_log(infile);
	}
	fclose(infile);
}
