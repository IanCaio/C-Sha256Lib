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
	unsigned char *msg;		//The message to be digested
	uint64_t bits_length;	//The message's length in bits

	unsigned char *preprocessed_msg;		//The preprocessed message, ready to be digested
	uint64_t preprocessed_bits_length;	//The preprocessed message length in bits (multiple of 512)

	unsigned char hash[32];	//The final hash

	char processed;	//Was the message already processed? 1 = processed / 0 = not processed
	char digested;	//Was the message already digested? 1 = digested / 0 = not digested

	struct sha256_list messages_list_entry;	//Linked list reference
};

//Main structure, containing some information needed for the digestion function
struct sha256_base {
	//Linked list entry to reference all messages added to this base structure
	struct sha256_list messages_list_entry;

	uint32_t HashValues[8];
	uint32_t RoundConstants[64];
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
struct sha256_message *sha256_message_create_from_buffer(const char *buffer, unsigned int bits_length, struct sha256_base *base);
int sha256_message_delete(struct sha256_message *message, struct sha256_base *base);
int sha256_message_preprocess(struct sha256_message *message);
void sha256_message_show(struct sha256_message *message);
void sha256_message_debug_bits(struct sha256_message *message);

//Logical Functions that will be used in the digest
uint32_t sha256_logical_func1(uint32_t x, uint32_t y, uint32_t z);
uint32_t sha256_logical_func2(uint32_t x, uint32_t y, uint32_t z);
uint32_t sha256_logical_func3(uint32_t x);
uint32_t sha256_logical_func4(uint32_t x);
uint32_t sha256_logical_func5(uint32_t x);
uint32_t sha256_logical_func6(uint32_t x);

//Digest function
void sha256_message_digest(struct sha256_message *message, struct sha256_base *base);

//Print hash in the screen
void sha256_message_show_hash(struct sha256_message *message);

//Returns the hash to a mallocated string and returns the pointer to it
char *sha256_message_get_hash(struct sha256_message *message);

#endif
