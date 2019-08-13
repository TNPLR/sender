#include "csd.h"

int recvall(int socketfd, void *buf, size_t buf_size, int flags)
{
	ssize_t sz = recv(socketfd, buf, buf_size, flags);
	if (sz == -1) {
		puts("Cannot receive message");
		return -1;
	}

	if (sz == 0) {
		puts("Connection closed");
		return -1;
	}
	while ((size_t)sz != buf_size) {
		ssize_t tmp = recv(socketfd, ((char *)buf + sz), buf_size - sz, flags);
		if (tmp == -1) {
			puts("Cannot receive message");
			return -1;
		}
		if (tmp == 0) {
			puts("Connection closed");
			return -1;
		}
		sz += tmp;
	}
	return 0;
}

int sendall(int socketfd, const void *buf, size_t buf_size, int flags)
{
	ssize_t sz = send(socketfd, buf, buf_size, flags);
	if (sz == -1) {
		return -1;
	}
	while ((size_t)sz != buf_size) {
		ssize_t tmp = send(socketfd, ((char *)buf + sz), buf_size - sz, flags);
		if (tmp == -1) {
			return -1;
		}
		sz += tmp;
	}
	return 0;
}

size_t recv_pack(int socketfd, void **buf, int flags)
{
	size_t buf_len;
	int sz = recvall(socketfd, &buf_len, sizeof buf_len, flags);
	if (sz) {
		perror("RECV_PACK:");
		puts("Get message length failed");
		return 0;
	} else if (buf_len > MAX_RECV_LEN) {
		puts("Message size too large");
		return 0;
	}

	*buf = calloc(1, buf_len);

	sz = recvall(socketfd, *buf, buf_len, flags);
	if (sz) {
		puts("Get message failed");
		return 0;
	}
	return buf_len;
}

size_t send_pack(int socketfd, const void *buf, size_t buf_size, int flags)
{
	int sz = sendall(socketfd, &buf_size, sizeof buf_size, flags);
	if (sz) {
		perror("SEND_PACK:");
		puts("Send message length failed");
		return 0;
	}

	sz = sendall(socketfd, buf, buf_size, flags);
	if (sz) {
		puts("Send message failed");
		return 0;
	}
	return buf_size;
}

static size_t get_arr_from_sexp(void **ptr, gcry_sexp_t sexp)
{
	size_t rsa_key_len = gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, NULL, 0);
	*ptr = calloc(1, rsa_key_len);
	if (ptr == NULL) {
		puts("Alloc memory for Sexp buffer failed");
		return 0;
	}
	gcry_sexp_sprint(sexp, GCRYSEXP_FMT_CANON, *ptr, rsa_key_len);
	return rsa_key_len;
}

int keypair_generator(const char *file_pos)
{
	gcry_sexp_t rsa_parms;
	gcry_sexp_t rsa_keypair;
	gcry_error_t err = 0;

	err = gcry_sexp_build(&rsa_parms, NULL, "(genkey (rsa (nbits 4:4096)))");
	if (err) {
		puts("Failed to generate rsa parameters");
		return 1;
	}

	puts("Key generation starts\nPlease wait...\n"
			"We are getting entropy on your system");
	err = gcry_pk_genkey(&rsa_keypair, rsa_parms);
	if (err) {
		puts("Failed to generate rsa keypair");
		gcry_sexp_release(rsa_parms);
		return 2;
	}
	puts("Key generation done");

	void *rsa_buffer;
	size_t rsa_key_len = get_arr_from_sexp(&rsa_buffer, rsa_keypair);

	FILE *fout = fopen(file_pos, "w");
	if (fout == NULL) {
		perror("Keypair Gen:");
		gcry_sexp_release(rsa_parms);
		gcry_sexp_release(rsa_keypair);
		free(rsa_buffer);
		return 4;
	}

	// Buffer length
	if (fwrite(&rsa_key_len, sizeof rsa_key_len, 1, fout) != 1) {
		perror("Keypair Gen:");
		gcry_sexp_release(rsa_parms);
		gcry_sexp_release(rsa_keypair);
		fclose(fout);
		free(rsa_buffer);
		return 5;
	}

	if (fwrite(rsa_buffer, rsa_key_len, 1, fout) != 1) {
		perror("Keypair Gen:");
		gcry_sexp_release(rsa_parms);
		gcry_sexp_release(rsa_keypair);
		fclose(fout);
		free(rsa_buffer);
		return 5;
	}

	fclose(fout);

	gcry_sexp_release(rsa_parms);
	gcry_sexp_release(rsa_keypair);
	free(rsa_buffer);
	return 0;
}

int read_keypair(gcry_sexp_t *pubk, gcry_sexp_t *privk, const void *file_pos)
{
	FILE *fin = fopen(file_pos, "r");
	if (fin == NULL) {
		perror("Read Keypair:");
		return 1;
	}

	size_t rsa_key_len;
	if (fread(&rsa_key_len, sizeof rsa_key_len, 1, fin) != 1) {
		puts("Cannot Read rsa_buffer");
		fclose(fin);
		return 3;
	}

	void *rsa_buffer = calloc(1, rsa_key_len);
	if (rsa_buffer == NULL) {
		puts("Cannot Alloc rsa_buffer");
		return 2;
	}

	if (fread(rsa_buffer, rsa_key_len, 1, fin) != 1) {
		puts("Cannot Read rsa_buffer");
		fclose(fin);
		free(rsa_buffer);
		return 3;
	}
	fclose(fin);

	gcry_error_t err = 0;
	gcry_sexp_t rsa_keypair;
	err = gcry_sexp_new(&rsa_keypair, rsa_buffer, rsa_key_len, 0);
	if (err) {
		free(rsa_buffer);
		puts("New Key failed");
		return 4;
	}
	*pubk = gcry_sexp_find_token(rsa_keypair, "public-key", 0);
	*privk = gcry_sexp_find_token(rsa_keypair, "private-key", 0);
	gcry_sexp_release(rsa_keypair);
	free(rsa_buffer);
	return 0;
}

int recv_rsa_key(int socketfd, gcry_sexp_t *pubk_buf)
{
	size_t keylen;
	void *buffer;

	keylen = recv_pack(socketfd, &buffer, 0);
	if (keylen == 0) {
		puts("Get key failed");
		return 2;
	}

	gcry_error_t err = gcry_sexp_new(pubk_buf, buffer, keylen, 0);
	free(buffer);
	if (err) {
		puts("Cannot create S Expression for the public key just received");
		return 3;
	}
	return 0;
}

int send_rsa_key(int socketfd, gcry_sexp_t pub_key)
{
	size_t keylen = gcry_sexp_sprint(pub_key, GCRYSEXP_FMT_CANON, NULL, 0);
	void *buffer = calloc(1, keylen);

	gcry_sexp_sprint(pub_key, GCRYSEXP_FMT_CANON, buffer, keylen);

	if (send_pack(socketfd, buffer, keylen, 0) == 0) {
		puts("Send key failed");
		return 2;
	}
	free(buffer);
	return 0;
}

int calculate_hash(void **res, const void *s, size_t s_size)
{
	gcry_md_hd_t hd;
	gcry_error_t err;
	err = gcry_md_open(&hd, GCRY_MD_SHA3_512, GCRY_MD_FLAG_SECURE);
	if (err) {
		puts("Cannot open md system");
		return -1;
	}

	gcry_md_write(hd, s, s_size);

	*res = calloc(1, 512);
	memcpy(*res, gcry_md_read(hd, 0), 512);

	gcry_md_close(hd);
	return 0;
}

static int verify_rsa_data(gcry_sexp_t pub_key, const void *plain, size_t plain_len,
		const void *signature, size_t sign_len)
{
	gcry_mpi_t msg;
	gcry_sexp_t sig;
	gcry_sexp_t data;
	gcry_error_t err;

	err = gcry_sexp_new(&sig, signature, sign_len, 0);
	if (err) {
		puts("Convert to S expression failed");
		return -1;
	}

	void *buffer;
	calculate_hash(&buffer, plain, plain_len);
	// 64 BYTE SHA-512
	err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buffer, 64, NULL);
	free(buffer);
	if (err) {
		gcry_sexp_release(data);
		puts("Cannot create mpi for the message");
		return -1;
	}

	err = gcry_sexp_build(&data, NULL,
			"(data (flags raw) (value %m))", msg);

	if (err) {
		gcry_sexp_release(data);
		gcry_mpi_release(msg);
		puts("Cannot create S expression for the message");
		return -1;
	}

	err = gcry_pk_verify(sig, data, pub_key);
	if (err) {
		gcry_mpi_release(msg);
		gcry_sexp_release(sig);
		gcry_sexp_release(data);
		puts("Cannot verify Message");
		return -1;
	}
	gcry_mpi_release(msg);
	gcry_sexp_release(data);
	gcry_sexp_release(sig);
	return 0;
}

static size_t sign_rsa_data(void **ptr, gcry_sexp_t priv_key, const void *s, size_t msg_len)
{
	gcry_mpi_t msg;
	gcry_sexp_t data;
	gcry_error_t err;

	void *buffer;
	calculate_hash(&buffer, s, msg_len);
	// 64 byte SHA-512
	err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, buffer, 64, NULL);
	free(buffer);
	if (err) {
		puts("Cannot create mpi for the message");
		return 0;
	}

	err = gcry_sexp_build(&data, NULL,
			"(data (flags raw) (value %m))", msg);

	if (err) {
		gcry_mpi_release(msg);
		puts("Cannot create S expression for the message");
		return 0;
	}

	gcry_sexp_t ciph;
	err = gcry_pk_sign(&ciph, data, priv_key);
	if (err) {
		gcry_mpi_release(msg);
		gcry_sexp_release(data);
		puts("Cannot Encrypt Message");
		return 0;
	}

	size_t data_size = get_arr_from_sexp(ptr, ciph);
	if (data_size == 0) {
		gcry_mpi_release(msg);
		gcry_sexp_release(data);
		gcry_sexp_release(ciph);
		free(*ptr);
		return 0;
	}
	gcry_mpi_release(msg);
	gcry_sexp_release(data);
	gcry_sexp_release(ciph);
	return data_size;
}

static size_t encrypt_rsa_data(void **ptr, gcry_sexp_t pub_key, const void *s, size_t msg_len)
{
	gcry_mpi_t msg;
	gcry_sexp_t data;
	gcry_error_t err;

	err = gcry_mpi_scan(&msg, GCRYMPI_FMT_USG, s, msg_len, NULL);
	if (err) {
		puts("Cannot create mpi for the message");
		return 0;
	}

	err = gcry_sexp_build(&data, NULL,
			"(data (flags raw) (value %m))", msg);

	if (err) {
		gcry_mpi_release(msg);
		puts("Cannot create S expression for the message");
		return 0;
	}

	gcry_sexp_t ciph;
	err = gcry_pk_encrypt(&ciph, data, pub_key);
	if (err) {
		gcry_mpi_release(msg);
		gcry_sexp_release(data);
		puts("Cannot Encrypt Message");
		return 0;
	}

	size_t data_size = get_arr_from_sexp(ptr, ciph);
	if (data_size == 0) {
		gcry_mpi_release(msg);
		gcry_sexp_release(data);
		gcry_sexp_release(ciph);
		free(*ptr);
		return 0;
	}
	gcry_mpi_release(msg);
	gcry_sexp_release(data);
	gcry_sexp_release(ciph);
	return data_size;
}

static size_t decrypt_rsa_data(void **ptr, gcry_sexp_t privk, const void *s, size_t msg_len)
{
	gcry_sexp_t ciph;
	gcry_sexp_t plain;
	gcry_error_t err;
	err = gcry_sexp_new(&ciph, s, msg_len, 0);
	if (err) {
		puts("Convert to S expression failed");
		return 0;
	}

	err = gcry_pk_decrypt(&plain, ciph, privk);
	if (err) {
		gcry_sexp_release(ciph);
		puts("Cannot decrypt message");
		return 0;
	}

	gcry_mpi_t msg = gcry_sexp_nth_mpi(plain, 0, GCRYMPI_FMT_USG);
	size_t ret;
	err = gcry_mpi_aprint(GCRYMPI_FMT_USG, (unsigned char **)ptr, &ret, msg);
	if (err) {
		gcry_sexp_release(ciph);
		gcry_sexp_release(plain);
		gcry_mpi_release(msg);
		puts("Cannot print mpi");
		return 0;
	}
	gcry_sexp_release(ciph);
	gcry_sexp_release(plain);
	gcry_mpi_release(msg);
	return ret;
}

size_t receive_and_decrypt(int socketfd, gcry_sexp_t pub_key,
		gcry_sexp_t priv_key, void **plain)
{
	size_t msg_size;
	struct connect_pack *pk;

	msg_size = recv_pack(socketfd, (void *)&pk, 0);
	if (msg_size == 0) {
		puts("Message size == 0");
		return 0;
	}

	size_t plain_size = decrypt_rsa_data(plain, priv_key, pk->ch, pk->buffer_size);
	if (plain_size == 0) {
		puts("Decrypt went wrong");
		free(pk);
		return 0;
	}
	if (verify_rsa_data(pub_key, *plain, plain_size,
				pk->ch + pk->buffer_size, pk->signature_size)) {
		free(*plain);
		free(pk);
		puts("Message signature not correct");
		return 0;
	}
	free(pk);
	return plain_size;
}

int encrypt_and_send(int socketfd, gcry_sexp_t pub_key, gcry_sexp_t priv_key,
		const void *s, size_t msg_size)
{
	void *edata;
	void *sig;
	size_t edata_size;
	size_t sig_size;
	edata_size = encrypt_rsa_data(&edata, pub_key, s, msg_size);
	sig_size = sign_rsa_data(&sig, priv_key, s, msg_size);

	struct connect_pack *pk =
		calloc(1, sizeof(struct connect_pack) + edata_size + sig_size);
	pk->buffer_size = edata_size;
	pk->signature_size = sig_size;
	pk->attribute = 0;
	memcpy(pk->ch, edata, edata_size);
	memcpy(pk->ch + edata_size, sig, sig_size);

	if (send_pack(socketfd, pk, sizeof(struct connect_pack) + edata_size + sig_size, 0) == 0) {
		free(edata);
		free(sig);
		free(pk);
		puts("Cannot send message");
		return -1;
	}

	free(edata);
	free(sig);
	free(pk);
	return 0;
}
