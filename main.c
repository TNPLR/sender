#include "csd.h"

gcry_sexp_t pubk;
gcry_sexp_t privk;
const char recv_magic[MAGIC_BUF_SIZE] = {0xe5, 0xbc, 0xb5, 0xe8, 0x8a, 0xb8, 0xe5,
	0x98, 0x89};
const char send_magic[MAGIC_BUF_SIZE] = {0xe6, 0x9d, 0x8e, 0xe6, 0x98, 0x80, 0xe8,
	0x87, 0xbb};
const char message_done[MAGIC_BUF_SIZE] = {0xe6, 0x9d, 0x8e, 0xe9, 0xa6, 0xa5, 0xe5,
	0xa6, 0x82};

enum r_mode {
	SERVER, CLIENT,
};

enum k_mode {
	READ_KEY, GEN_KEY
};

static int print_help(void)
{
	puts("-h\t\tprint help page\n"
			"-c\t\tclient mode\n"
			"-s\t\tserver mode\n"
			"-a address\tset connect address\n"
			"-g\t\tkey generation mode\n"
			"-f file\t\tset keyfile\n"
			"-v\t\tverbose server message");
	return 0;
}

void clean_key(void)
{
	gcry_sexp_release(pubk);
	gcry_sexp_release(privk);
}


void signal_handler(int signum)
{
	switch (signum) {
	case SIGTERM:
	case SIGQUIT:
		exit(0);
		break;
	case SIGINT:
	default:
		exit(-1);
		break;
	}
}

int main(int argc, char *argv[])
{
	enum r_mode r = CLIENT;
	enum k_mode k = READ_KEY;
	int c;
	const char *ip_addr;
	const char *key_file = NULL;
	int port;
	while ((c = getopt(argc, argv, "chsa:p:gf:t")) != -1) {
		switch (c) {
		case 'c':
			r = CLIENT;
			break;
		case 'h':
			print_help();
			return 0;
		case 's':
			r = SERVER;
			break;
		case 'a':
			ip_addr = optarg;
			break;
		case 'p':
			sscanf(optarg, "%d", &port);
			break;
		case 'g':
			k = GEN_KEY;
			break;
		case 'f':
			key_file = optarg;
			break;
		case '\?':
			puts("Error while reading arguments");
			return -1;
		default:
			return -1;
		}
	}

	if (key_file == NULL) {
		puts("Please specify key file");
		return -1;
	}

	// Get our keypair
	if (k == READ_KEY) {
		if (read_keypair(&pubk, &privk, key_file)) {
			puts("Cannot read key");
			return -1;
		}
		if (atexit(clean_key)) {
			puts("Cannot register exit function");
			return -1;
		}
	} else if (k == GEN_KEY) {
		if (keypair_generator(key_file)) {
			puts("Cannot generate key");
			return -1;
		}
		return 0;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	gcry_check_version(NULL);

	gcry_control(GCRYCTL_ENABLE_M_GUARD);

	if (r == SERVER) {
		receiver();
	} else if (r == CLIENT) {
		tui_client(ip_addr);
	}
	return 0;
}
