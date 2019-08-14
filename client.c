#include "csd.h"

uintmax_t message_count;
static int send_msg_to_server(int socketfd, gcry_sexp_t pub_key, const void *s, size_t msg_size)
{
	return encrypt_and_send(socketfd, pub_key, privk, s, msg_size);
}

static int receive_server_msg(int socketfd, gcry_sexp_t pub_key, WINDOW *win, int maxy)
{
	int y = 0;

	uint32_t count;

	if (recvall(socketfd, &count, sizeof count, 0)) {
		puts("Cannot receive count");
		return -1;
	}

	werase(win);

	for (uint32_t i = 0; i < count; ++i) {
		void *plain;
		size_t length;

		if (!(length = receive_and_decrypt(socketfd, pub_key, privk, &plain))) {
			break;
		}

		//append_list(length, plain);
		if (y + 3 > maxy - 5) {
			wscrl(win, 3);
			y -= 3;
		}

		char buffer[64];
		++message_count;
		strftime(buffer, 64, "%Ec", localtime(&((struct message *)plain)->tm));
		mvwprintw(win, y, 0, "[%s] %s", buffer, ((struct message *)plain)->s);
		y += 3;
		gcry_free(plain);
	}
	wrefresh(win);
	return 0;
}

// return socket
static struct addrinfo *server_addr;
static void clean_addrinfo(void)
{
	freeaddrinfo(server_addr);
}
static int client_protocol(const char *username, const char *saddr, gcry_sexp_t *pub_key)
{
	struct addrinfo hints = {0};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	int status;
	if ((status = getaddrinfo(saddr, LISTEN_PORT_STR, &hints, &server_addr)) != 0) {
		printf("getaddrinfo error: %s\n", gai_strerror(status));
		return -1;
	}

	if (atexit(clean_addrinfo)) {
		puts("Cannot load exit function");
		return -1;
	}

	char buf[MAGIC_BUF_SIZE];
	int socketfd = socket(server_addr->ai_family, server_addr->ai_socktype, server_addr->ai_protocol);
	if (socketfd == -1) {
		puts("Cannot create socket");
		return -1;
	}

	if (connect(socketfd, server_addr->ai_addr, server_addr->ai_addrlen) == -1) {
		puts("Cannot connect to the server");
		return -1;
	}

	// Send recv_magic
	if (sendall(socketfd, recv_magic, sizeof recv_magic, 0)) {
		puts("Cannot send receive magic");
		return -1;
	}

	// Receive magic
	if (recvall(socketfd, buf, sizeof send_magic, 0)) {
		puts("Magic not correct");
		return -1;
	}

	if (memcmp(send_magic, buf, sizeof send_magic)) {
		puts("Magic not correct");
		return -1;
	}

	if (recv_rsa_key(socketfd, pub_key)) {
		puts("Cannot get rsa key");
		return -1;
	}

	if (send_rsa_key(socketfd, pubk)) {
		puts("Cannot send rsa key");
		return -1;
	}

	void *rand_msg;
	size_t sz;
	if (!(sz = receive_and_decrypt(socketfd, *pub_key, privk, &rand_msg))) {
		puts("Cannot receive random message");
		return -1;
	}

	if (encrypt_and_send(socketfd, *pub_key, privk, rand_msg, sz)) {
		puts("Cannot send back random message");
		return -1;
	}

	gcry_free(rand_msg);
	return socketfd;
}

static WINDOW *create_newwin(int height, int width, int starty, int startx)
{
	WINDOW *local_win;
	local_win = newwin(height, width, starty, startx);
	refresh();

	return local_win;
}

static void destroy_win(WINDOW *local_win)
{
	delwin(local_win);
}

static gcry_sexp_t pub_key;

static void cleanup_key(void)
{
	gcry_sexp_release(pub_key);
}

static int message_proc(int socketfd, gcry_sexp_t pub_key, WINDOW *win, int maxy)
{
	enum server_rq rq = GET_MSG;

	if (sendall(socketfd, &rq, sizeof rq, 0)) {
		puts("Cannot send GET_MSG");
		return 1;
	}
	receive_server_msg(socketfd, pub_key, win, maxy);

	return 0;
}

static int send_proc(const char *username, const char *saddr)
{
	int maxy, maxx;
	getmaxyx(stdscr, maxy, maxx);

	WINDOW *message_win = create_newwin(maxy - 5, maxx, 0, 0);
	WINDOW *send_win = create_newwin(5, maxx, maxy - 5, 0);

	wborder(send_win, '|', '|', '-','-','+','+','+','+');
	wrefresh(send_win);
	refresh();

	scrollok(message_win, 1);
	refresh();
	char buffer[1024];
	int bf = 0;
	int cur_y = 1, cur_x = 1;
	refresh();

	int socketfd = client_protocol(username, saddr, &pub_key);
	if (socketfd == -1) {
		puts("Cannot Protocol");
		destroy_win(send_win);
		destroy_win(message_win);
		shutdown(socketfd, 2);
		return 1;
	}

	// Initialize connection
	enum server_rq rq;

	message_proc(socketfd, pub_key, message_win, maxy);
	while (1) {
		wmove(send_win, cur_y, cur_x);
		wrefresh(send_win);
		int c = getch();
		switch (c) {
		case 0x3: // Ctrl - C
		case 0x1B: // ESC
		case KEY_EXIT:
			rq = END_OF_CMD;
			if (sendall(socketfd, &rq, sizeof rq, 0)) {
				puts("Cannot send END_OF_CMD");
				destroy_win(send_win);
				destroy_win(message_win);
				shutdown(socketfd, 2);
				return 1;
			}
			destroy_win(send_win);
			destroy_win(message_win);
			shutdown(socketfd, 2);
			return 0;
		case KEY_F(5):
			message_proc(socketfd, pub_key, message_win, maxy);
			break;
		case '\r':
		case '\n':
		case KEY_ENTER:
			rq = SEND_MSG;
			if (sendall(socketfd, &rq, sizeof rq, 0)) {
				puts("Cannot send SEND_MSG");
				destroy_win(send_win);
				destroy_win(message_win);
				shutdown(socketfd, 2);
				return 1;
			}
			buffer[bf++] = '\0';
			send_msg_to_server(socketfd, pub_key, buffer, bf);
			wclear(send_win);
			wborder(send_win, '|', '|', '-','-','+','+','+','+');
			cur_y = 1;
			cur_x = 1;
			bf = 0;
			message_proc(socketfd, pub_key, message_win, maxy);
			break;
		case '\b':
		case KEY_BACKSPACE:
			if (bf > 0) {
				buffer[--bf] = '\0';
			}
			if (--cur_x == 0) {
				if (cur_y > 1) {
					cur_x = maxx - 1;
					--cur_y;
				} else {
					cur_x = 1;
				}
			}
			mvwaddch(send_win, cur_y, cur_x, ' ');
			break;
		default:
			buffer[bf++] = c;
			mvwaddch(send_win, cur_y, cur_x, c);
			if (bf > 1023) {
				bf = 1023;
				break;
			}
			if (++cur_x > maxx - 2) {
				if (cur_y < 2) {
					++cur_y;
					cur_x = 1;
				} else {
					--cur_x;
				}
			}
			break;
		}
	}
	return 1;
}

int tui_client(const char *username, const char *saddr)
{
	atexit(cleanup_key);

	setlocale(LC_ALL, "");
	initscr();
	raw();
	noecho();

	keypad(stdscr, TRUE);

	send_proc(username, saddr);

	endwin();
	return 0;
}
