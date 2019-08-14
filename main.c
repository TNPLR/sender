#include "csd.h"

#include <getopt.h>

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
	puts("sender version "VERSION"\n"
			"-h\t--help\t\t\tprint help page\n"
			"-c\t--client\t\tclient mode\n"
			"-s\t--server\t\tserver mode\n"
			"-a\t--address <address>\tset connect address\n"
			"-g\t--genkey\t\tkey generation mode\n"
			"-f\t--file <file>\t\tset keyfile\n"
			"-u\t--user <username>\tset username\n" 
			"-r\t--readonly\t\tServer public key Read Only\n"
			"-w\t--write\t\t\tWrite new key if the user is unknown\n"
			"-W\t--always-write\t\tWrite new key no matter the user is known or not");
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
static struct option long_option[] = {
	{"client", no_argument, NULL, 'c'},
	{"help", no_argument, NULL, 'h'},
	{"server", no_argument, NULL, 's'},
	{"address", required_argument, NULL, 'a'},
	{"port", required_argument, NULL, 'p'},
	{"genkey", no_argument, NULL, 'g'},
	{"file", required_argument, NULL, 'f'},
	{"user", required_argument, NULL, 'u'},
	{"readonly", no_argument, NULL, 'r'},
	{"ro", no_argument, NULL, 'r'},
	{"write", no_argument, NULL, 'w'},
	{"always-write", no_argument, NULL, 'W'},
	{NULL, 0, NULL, 0},
};
int main(int argc, char *argv[])
{
	enum r_mode r = CLIENT;
	enum k_mode k = READ_KEY;
	int c;
	const char *ip_addr = NULL;
	const char *key_file = NULL;
	const char *username = NULL;
	int port;

	int long_option_code;
	while ((c = getopt_long(argc, argv, "chsa:p:gf:u:rwW",
					long_option, &long_option_code)) != -1) {
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
		case 'u':
			username = optarg;
			break;
		case 'r':
			key_mode = READONLY;
			break;
		case 'w':
			key_mode = NEW_INSERT;
			break;
		case 'W':
			key_mode = NEW_REPLACE;
			break;
		case '\?':
			puts("Error while reading arguments");
			print_help();
			return -1;
		default:
			return -1;
		}
	}

	gcry_check_version(NULL);

	gcry_error_t err;
	err = gcry_control(GCRYCTL_ENABLE_M_GUARD);

	err |= gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

	err |= gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);

	err |= gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

	err |= gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

	if (err) {
		puts("Init failed");
		return -1;
	}

	if (key_file == NULL) {
		puts("Please specify key file");
		print_help();
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

	if (r == SERVER) {
		receiver();
	} else if (r == CLIENT) {
		if (username == NULL) {
			puts("Please specify username");
			print_help();
			return -1;
		}
		if (ip_addr == NULL) {
			puts("Please specify ip address or hostname");
			print_help();
			return -1;
		}
		tui_client(username, ip_addr);
	}
	return 0;
}
