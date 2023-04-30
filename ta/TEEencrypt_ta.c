#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>
#include <string.h>
#include <stdio.h>

#define RSA_KEY_SIZE 1024
#define MAX_PLAIN_LEN_1024 86
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

struct rsa_session {
	TEE_OperationHandle op_handle;	
	TEE_ObjectHandle key_handle; 
};

unsigned int random_key;
int root_key = 11;

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}


void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}


TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                            TEE_Param __maybe_unused params[4],
                            void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE,
                                    TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	struct rsa_session *sess;
	sess = TEE_Malloc(sizeof(*sess), 0);

	if (!sess) return TEE_ERROR_OUT_OF_MEMORY;

	sess->key_handle = TEE_HANDLE_NULL;
	sess->op_handle = TEE_HANDLE_NULL;
	
	*sess_ctx = (void *)sess;

	DMSG("\nSession %p: newly allocated\n", *sess_ctx);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx;
	IMSG("Goodbye!\n");
}

static TEE_Result create_randomkey(uint32_t param_types, TEE_Param params[4])
{
	DMSG("====================Create Random Key====================\n");
	TEE_GenerateRandom(&random_key, sizeof(random_key));
	random_key = random_key % 26;
	while (random_key == 0) {
		TEE_GenerateRandom(&random_key, sizeof(random_key));
		random_key = random_key % 26;
	}
	
	IMSG("Create New RandomKey : %d\n", random_key);

	return TEE_SUCCESS;
}

static TEE_Result enc_randomkey(uint32_t param_types, TEE_Param params[4])
{
	DMSG("====================Encryption(Random Key)====================\n");

	if (random_key >= 'a' && random_key <= 'z') {
		random_key -= 'a';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key += root_key;
		random_key = random_key % 26;
		random_key += 'A';
	}
	params[1].value.a = (uint32_t)random_key;

	return TEE_SUCCESS;
}

static TEE_Result dec_randomkey(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [1024]={0,};	
	
	DMSG("====================Decryption(Random Key)====================\n");
	memcpy(encrypted, in, in_len);
	random_key = encrypted[in_len-1];

	if (random_key >= 'a' && random_key <= 'z') {
		random_key -= 'a';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'a';
	}
	else if (random_key >= 'A' && random_key <= 'Z') {
		random_key -= 'A';
		random_key -= root_key;
		random_key += 26;
		random_key = random_key % 26;
		random_key += 'A';
	}
	IMSG("Got value: %c from NW\n", encrypted[in_len-1]);
	IMSG("Decrypted RandomKey : %d\n", random_key);
	
	params[1].value.a = (uint32_t) random_key;

	return TEE_SUCCESS;
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4])
{
	DMSG("ENC_VALUE has been called");

	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [1024] = {0,};

	memcpy(encrypted, in, in_len);

	for (int i = 0; i < in_len; i++) {
		if (encrypted[i] >= 'a' && encrypted[i] <= 'z') {
			encrypted[i] -= 'a';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += random_key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	memcpy(in, encrypted, in_len);
	DMSG ("Ciphertext :  %s", encrypted);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [1024]={0,};
	
	DMSG("====================Decryption====================\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, in_len);

	for (int i = 0; i < in_len - 1; i++) {
		if (decrypted[i] >= 'a' && decrypted[i] <='z') {
			decrypted[i] -= 'a';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= random_key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	decrypted[in_len-1] = '\0';
	DMSG ("Plaintext :  %s", decrypted);
	memcpy(in, decrypted, in_len);

	return TEE_SUCCESS;
}

TEE_Result prepare_rsa_operation(TEE_OperationHandle *handle, uint32_t alg,
		TEE_OperationMode mode, TEE_ObjectHandle key) 
{
	TEE_Result ret = TEE_SUCCESS;	
	TEE_ObjectInfo key_info;
	ret = TEE_GetObjectInfo1(key, &key_info);
	if (ret != TEE_SUCCESS) {
		return ret;
	}

	ret = TEE_AllocateOperation(handle, alg, mode, key_info.keySize);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc operation handle : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	ret = TEE_SetOperationKey(*handle, key);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to set key : 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Operation key already set. ==========\n");

	return ret;
}

TEE_Result check_params(uint32_t param_types) {
	const uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
                TEE_PARAM_TYPE_MEMREF_OUTPUT,
                TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);

	/* Safely get the invocation parameters */
	if (param_types != exp_param_types) return TEE_ERROR_BAD_PARAMETERS;
	return TEE_SUCCESS;
}

TEE_Result RSA_create_key_pair(void *session) {
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *sess = (struct rsa_session *)session;
	
	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(sess->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS) {
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

TEE_Result RSA_encrypt(void *session, uint32_t param_types, TEE_Param params[4]) {
	TEE_Result ret;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)session;

	if (check_params(param_types) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	ret = prepare_rsa_operation(&sess->op_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", ret);
		goto err;
	}

	DMSG("\nData to encrypt: %s\n", (char *) plain_txt);
	ret = TEE_AsymmetricEncrypt(sess->op_handle, (TEE_Attribute *)NULL, 0, plain_txt, plain_len, cipher, &cipher_len);					
	if (ret != TEE_SUCCESS) {
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", ret);
		goto err;
	}
	DMSG("\nEncrypted data: %s\n", (char *) cipher);
	DMSG("\n========== Encryption successfully ==========\n");
	return ret;

err:
	TEE_FreeOperation(sess->op_handle);
	TEE_FreeOperation(sess->key_handle);
	return ret;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
                                    uint32_t cmd_id,
                                    uint32_t param_types, 
                                    TEE_Param params[4])
{
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_CREATE_RANDOMKEY:
		return create_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_ENC_RANDOMKEY:
		return enc_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_DEC_RANDOMKEY:
		return dec_randomkey(param_types, params);
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_RSA_CMD_GENKEYS:
		return RSA_create_key_pair(sess_ctx);
	case TA_RSA_CMD_ENCRYPT:
		return RSA_encrypt(sess_ctx, param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

