#include "csd.h"

static size_t decrypt_aes_data(const void *key, size_t key_len,
		const void *iv, size_t iv_len, const void *s, size_t msg_len)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;
	err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (err) {
		puts("Cannot open AES cipher");
		return 0;
	}

	err = gcry_cipher_setkey(hd, key, key_len);
	if (err) {
		puts("Cannot set key");
		return 0;
	}

	err = gcry_cipher_setiv(hd, iv, iv_len);
	if (err) {
		puts("Cannot set iv");
		return 0;
	}

	err = gcry_cipher_decrypt(hd, (unsigned char *)s, msg_len, NULL, 0);
	gcry_cipher_close(hd);
	if (err) {
		puts("Cannot decrypt AES");
		return 0;
	}
	return msg_len;
}

static size_t encrypt_aes_data(const void *key, size_t key_len,
		const void *iv, size_t iv_len, const void *s, size_t msg_len)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd;
	err = gcry_cipher_open(&hd, GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (err) {
		puts("Cannot open AES cipher");
		return 0;
	}

	err = gcry_cipher_setkey(hd, key, key_len);
	if (err) {
		puts("Cannot set key");
		return 0;
	}

	err = gcry_cipher_setiv(hd, iv, iv_len);
	if (err) {
		puts("Cannot set iv");
		return 0;
	}

	err = gcry_cipher_encrypt(hd, (unsigned char *)s, msg_len, NULL, 0);
	gcry_cipher_close(hd);
	if (err) {
		puts("Cannot encrypt AES");
		return 0;
	}
	return msg_len;
}

static int verify_hmac_data(void *hmac, size_t hmac_size,
		const void *key, size_t key_len,
		const void *s, size_t msg_len)
{
	gcry_error_t err;
	gcry_mac_hd_t hd;
	err = gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA3_512,
			GCRY_MAC_FLAG_SECURE, NULL);
	if (err) {
		puts("Cannot open HMAC_SHA3");
		return 1;
	}

	err = gcry_mac_setkey(hd, key, key_len);
	if (err) {
		puts("Cannot set key");
		return 1;
	}

	err = gcry_mac_write(hd, s, msg_len);
	if (err) {
		puts("Cannot write to HMAC");
		return 1;
	}

	err = gcry_mac_read(hd, hmac, &hmac_size);
	gcry_mac_close(hd);
	if (err) {
		puts("Cannot read HMAC");
		return 1;
	}
	return 0;
}

static size_t get_hmac_data(void **ptr, const void *key, size_t key_len,
		const void *s, size_t msg_len)
{
	gcry_error_t err;
	gcry_mac_hd_t hd;
	err = gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA3_512,
			GCRY_MAC_FLAG_SECURE, NULL);
	if (err) {
		puts("Cannot open HMAC_SHA3");
		return 0;
	}

	err = gcry_mac_setkey(hd, key, key_len);
	if (err) {
		puts("Cannot set key");
		return 0;
	}

	err = gcry_mac_write(hd, s, msg_len);
	if (err) {
		puts("Cannot write to HMAC");
		return 0;
	}

	size_t buffer_size = gcry_mac_get_algo_maclen(GCRY_MAC_HMAC_SHA3_512);
	*ptr = calloc(1, buffer_size);
	if (*ptr == NULL) {
		puts("Cannot alloc memory");
		return 0;
	}

	err = gcry_mac_read(hd, *ptr, &buffer_size);
	gcry_mac_close(hd);
	if (err) {
		free(*ptr);
		puts("Cannot read HMAC");
		return 0;
	}
	return buffer_size;
}

size_t aes_receive_and_decrypt(int socketfd, const void *key,
		size_t key_size, void **plain)
{
	size_t msg_size;
	struct connect_aes_pack *pk;

	msg_size = recv_pack(socketfd, (void *)&pk, 0);
	if (msg_size == 0) {
		puts("Message size == 0");
		return 0;
	}

	size_t plain_size = decrypt_aes_data(key, key_size,
			pk->iv, sizeof pk->iv, pk->ch, pk->buffer_size);
	if (plain_size == 0) {
		puts("Decrypt went wrong");
		free(pk);
		return 0;
	}

	if (verify_hmac_data(pk->ch + pk->buffer_size,
				pk->hmac_size, key, key_size,
				pk->ch, pk->buffer_size)) {
		puts("Message signature not correct");
		free(pk);
		return 0;
	}

	*plain = calloc(1, plain_size);
	if (*plain == NULL) {
		puts("Cannot alloc memory");
		return 0;
	}
	memcpy(*plain, pk->ch, pk->buffer_size);
	free(pk);
	return plain_size;
}

int aes_encrypt_and_send(int socketfd, const void *key, size_t key_size,
		const void *s, size_t msg_size)
{
	void *sig;

	char iv[16];
	gcry_randomize(iv, sizeof iv, GCRY_VERY_STRONG_RANDOM);

	size_t edata_size = (msg_size & ~0xF) + ((!!(msg_size & 0xF)) << 4);
	assert(edata_size >= msg_size);
	size_t sig_size;
	void *edata = calloc(1, edata_size);
	memcpy(edata, s, msg_size);
	sig_size = get_hmac_data(&sig, key, key_size, edata, edata_size);
	edata_size = encrypt_aes_data(key, key_size, iv, sizeof iv, edata, edata_size);

	struct connect_aes_pack *pk =
		calloc(1, sizeof(struct connect_aes_pack) + edata_size + sig_size);
	pk->buffer_size = edata_size;
	pk->hmac_size = sig_size;
	pk->attribute = 0;
	memcpy(pk->iv, iv, sizeof iv);
	memcpy(pk->ch, edata, edata_size);
	memcpy(pk->ch + edata_size, sig, sig_size);
#if DEBUG == 2
	printf("Encrypt Size %lu Sign size %lu\n", edata_size, sig_size);
#endif

	if (send_pack(socketfd, pk, sizeof(struct connect_aes_pack) + edata_size + sig_size, 0) == 0) {
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

#if 0
int main()
{
	char key[32];
	char iv[16];
	char data[16] = "I love you!!!!!";
	puts(data);
	gcry_randomize(key, sizeof key, GCRY_VERY_STRONG_RANDOM);
	gcry_randomize(iv, sizeof iv, GCRY_VERY_STRONG_RANDOM);
	encrypt_aes_data(key, sizeof key, iv, sizeof iv, data, sizeof data);
	decrypt_aes_data(key, sizeof key, iv, sizeof iv, data, sizeof data);
	puts(data);
}
#endif
