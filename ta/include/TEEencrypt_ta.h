#ifndef TA_TEEencrypt_H
#define TA_TEEencrypt_H
#define TA_TEEencrypt_UUID \
	{ 0x5f193e3e, 0x2a4e, 0x425b, \
		{ 0xbf, 0x6c, 0x9d, 0x52, 0xb6, 0xcc, 0x84, 0x14} }

/* The function IDs implemented in this TA */
#define TA_TEEencrypt_CMD_CREATE_RANDOMKEY	0
#define TA_TEEencrypt_CMD_ENC_RANDOMKEY		1
#define TA_TEEencrypt_CMD_DEC_RANDOMKEY		2
#define TA_TEEencrypt_CMD_ENC_VALUE		3
#define TA_TEEencrypt_CMD_DEC_VALUE		4
#define TA_RSA_CMD_GENKEYS			5
#define TA_RSA_CMD_ENCRYPT			6

#endif /*TA_TEEencrypt_H*/
