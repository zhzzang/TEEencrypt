#include <err.h>
#include <stdio.h>
#include <string.h>
#include <tee_client_api.h>
#include <TEEencrypt_ta.h>

#include <fcntl.h>     
#include <unistd.h>   

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

#define CAESAR_ENCRYPT 0
#define CAESAR_DECRYPT 1
#define RSA_ENCRYPT    2

struct ta_attrs {
	TEEC_Context ctx;
	TEEC_Session sess;
};

void prepare_ta_session(struct ta_attrs *ta)
{
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t origin;
	TEEC_Result res;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ta->ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InitializeContext failed with code 0x%x\n", res);

	/* Open a session with the TA */
	res = TEEC_OpenSession(&ta->ctx, &ta->sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_Opensession failed with code 0x%x origin 0x%x\n", res, origin);
}

void terminate_tee_session(struct ta_attrs *ta)
{
	TEEC_CloseSession(&ta->sess);
	TEEC_FinalizeContext(&ta->ctx);
}

void prepare_op(TEEC_Operation *op, char *in, size_t in_sz, char *out, size_t out_sz) {
	memset(op, 0, sizeof(*op));

	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						TEEC_MEMREF_TEMP_OUTPUT,
						TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = in;
	op->params[0].tmpref.size = in_sz;
	op->params[1].tmpref.buffer = out;
	op->params[1].tmpref.size = out_sz;
}

void rsa_gen_keys(struct ta_attrs *ta) {
	TEEC_Result res;

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_GENKEYS, NULL, NULL);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
	printf("\n=========== Keys already generated. ==========\n");
}

void rsa_encrypt(struct ta_attrs *ta, char *in, size_t in_sz, char *out, size_t out_sz)
{
	TEEC_Operation op;
	uint32_t origin;
	TEEC_Result res;

	printf("\n============ RSA ENCRYPT CA SIDE ============\n");
	prepare_op(&op, in, in_sz, out, out_sz);

	res = TEEC_InvokeCommand(&ta->sess, TA_RSA_CMD_ENCRYPT, &op, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",
			res, origin);
	printf("\nThe text sent was encrypted: %s\n", out);
}


int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;

	struct ta_attrs ta;
	char plaintext[1024] = {0,};
	char ciphertext[1024] = {0,};
	char encrypted_randomkey[3];
	int len = 1024;
	int kindOfwork;
	char *enc_option = "-e";
	char *dec_option = "-d";
	char *caesar_option = "Caesar";
	char *rsa_option = "RSA";
	int fd;

	// Check TEE option
	if (argc > 4 || argc <= 2) {
		printf("Please check the execution options.\n");
		return 1;
	}

	if (argc == 3) {
		if (!strcmp(enc_option, argv[1]))
			kindOfwork = CAESAR_ENCRYPT;
		if (!strcmp(dec_option, argv[1]))
			kindOfwork = CAESAR_DECRYPT;
	} else if (!strcmp(caesar_option, argv[3])) {
		if (!strcmp(enc_option, argv[1]))
			kindOfwork = CAESAR_ENCRYPT;
		if (!strcmp(dec_option, argv[1]))
			kindOfwork = CAESAR_DECRYPT;
	} else if (!strcmp(rsa_option, argv[3]) && !strcmp(enc_option, argv[1])) {
			kindOfwork = RSA_ENCRYPT;
	} else {
		printf("Please check the execution options.\n");
		return 1;
	}

	// Encrypt or Decrypt
	switch(kindOfwork) {
		// 1) CAESAR Encryption
		case CAESAR_ENCRYPT:

			// Connect
			res = TEEC_InitializeContext(NULL, &ctx);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

			res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);

			// Read File
			fd = open(argv[2], O_RDONLY);
			if (fd == -1) {
				printf("fail");
				return 1;
			} else {
				read(fd, plaintext, len);
				close(fd);
			}

			// Set Parameter
			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
			op.params[0].tmpref.buffer = plaintext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, plaintext, len);

			// Encrypt : create randomkey -> encrypt plaintext -> encrypt randomkey(by rootkey)
			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_CREATE_RANDOMKEY, &op, &err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_RANDOMKEY, &op, &err_origin);

			memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	
			encrypted_randomkey[0] = op.params[1].value.a;
			encrypted_randomkey[1] = '\0';
			strcat(ciphertext, encrypted_randomkey);

			// File write
			if (0 < (fd = creat("./ciphertext.txt", 0644))) {
				write(fd, ciphertext, strlen(ciphertext));
				close(fd);
			} else {
				printf("fail");
				return 1;
			}
			
			printf("CAESAR Encryption complete!\n");

			// Disconnect
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			break;

		// 2) CAESAR Decryption
		case CAESAR_DECRYPT:

			// Connect
			res = TEEC_InitializeContext(NULL, &ctx);
			if (res != TEEC_SUCCESS)
				errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

			res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
			
            if (res != TEEC_SUCCESS)
				errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
					res, err_origin);
			fd = open(argv[2], O_RDONLY);

			// File read
			if (fd == -1) {
				printf("fail");
				return 1;
			} else {
				read(fd, ciphertext, len);
				close(fd);
			}

			// Set parameter
			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
			op.params[0].tmpref.buffer = ciphertext;
			op.params[0].tmpref.size = len;
			memcpy(op.params[0].tmpref.buffer, ciphertext, len);

			res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_RANDOMKEY, &op, &err_origin);
                         
	        char decrypted_randomkey[4];
            unsigned int k = op.params[1].value.a; 
            sprintf(decrypted_randomkey, "%u", k); 
			
            res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

			memcpy(plaintext, op.params[0].tmpref.buffer, len);

			strcat(plaintext, decrypted_randomkey);

			// File create, write
			if (0 < (fd = creat("./plaintext.txt", 0644))) {
				write(fd, plaintext, strlen(plaintext));
				close(fd);
			} else {
				printf("fail");
				return 1;
			}
			printf("CAESAR Decryption complete!\n");

			// Disconnect
			TEEC_CloseSession(&sess);
			TEEC_FinalizeContext(&ctx);
			break;

		// 3) RSA Encryption
		case RSA_ENCRYPT:

			// Connect
			prepare_ta_session(&ta);

			// File read
			fd = open(argv[2], O_RDONLY);
			if (fd == -1) {
				printf("fail");
				return 1;
			} else {
				read(fd, plaintext, RSA_MAX_PLAIN_LEN_1024);
				close(fd);
			}
			
			// Encrypt : create key -> encrypt
			rsa_gen_keys(&ta);
			rsa_encrypt(&ta, plaintext, RSA_MAX_PLAIN_LEN_1024, ciphertext, RSA_CIPHER_LEN_1024);

			// Create file, write						
			if (0 < (fd = creat("./ciphertext.txt", 0644))) {
				write(fd, ciphertext, strlen(ciphertext));
				close(fd);
			} else {
				printf("fail");
				return 1;
			}
			printf("RSA Encryption complete!\n");

			// Disconnect
			terminate_tee_session(&ta);
			break;

		default:
			break;
			
	}
	return 0;
}

