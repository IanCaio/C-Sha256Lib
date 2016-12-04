#ifndef _SHA256_DIGEST_H
#define _SHA256_DIGEST_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/*
=======================
	MACROS
=======================
*/

//i.e.: RIGHTROTATE_8(10101100, 3) => 00010101 | 10000000 => 10010101
#define RIGHTROTATE_32(x,y) (((x) >> (y)) | ((x) << (32 - (y))))
#define LEFTROTATE_32(x,y) (((x) << (y)) | ((x) >> (32 - (y))))

/*
==========================
	STRUCTURES
==========================
*/

//Linked list implementation
struct sha256_list{
	void *prev;
	void *next;
};

//Message structure (a message needs to be created and parsed to the digesting function)
struct sha256_message{
	char *msg;		//The message to be digested
	uint64_t bits_length;	//The message's length in bits

	char *preprocessed_msg;		//The preprocessed message, ready to be digested
	uint64_t preprocessed_bits_length;	//The preprocessed message length in bits (multiple of 512)

	char hash[33];	//The final hash

	struct sha256_list messages_list_entry;	//Linked list reference
};

//Main structure, containing some information needed for the digestion function
struct sha256_base {
	//Linked list entry to reference all messages added to this base structure
	struct sha256_list messages_list_entry;

	uint32_t HashValues[8];
	uint32_t RoundConstants[64];

	uint32_t msg_schedule[64];
};

/*
===================================
	FUNCTION PROTOTYPES
===================================
*/

void sha256_err(int error_code, const char *file_name, const char *function_name, unsigned int line);
void sha256_warn(const char *warning_msg, const char *file_name, const char *function_name, unsigned int line);
struct sha256_base *sha256_init();
void sha256_free(struct sha256_base *base);
struct sha256_message *sha256_message_create_from_string(const char *string, struct sha256_base *base);
int sha256_message_delete(struct sha256_message *message, struct sha256_base *base);
int sha256_message_preprocess(struct sha256_message *message);
void sha256_message_show(struct sha256_message *message);
void sha256_message_debug_bits(struct sha256_message *message);
int sha256_big_endian(void);
int sha256_little_endian(void);

#endif
