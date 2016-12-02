#ifndef _SHA512_DIGEST_H
#define _SHA512_DIGEST_H

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
struct sha512_list{
	void *prev;
	void *next;
};

struct sha512_message{
	char *Message;
	uint64_t BitsLength;
	char *PreProcessedMessage;

	struct sha512_list messages_list_entry;
};

struct sha512_base {
	//Linked list entry to reference all messages added to this base structure
	struct sha512_list messages_list_entry;

	uint32_t HashValues[8];
	uint32_t RoundConstants[64];

	uint32_t MessageSchedule[64];
};

/*
===================================
	FUNCTION PROTOTYPES
===================================
*/

void sha512_err(int error_code, const char *file_name, const char *function_name, unsigned int line);
void sha512_warn(const char *warning_msg, const char *file_name, const char *function_name, unsigned int line);
struct sha512_base *sha512_init();
void sha512_free(struct sha512_base *base);
struct sha512_message *sha512_message_create_from_string(const char *string, struct sha512_base *base);
int sha512_message_delete(struct sha512_message *message, struct sha512_base *base);
void sha512_message_preprocess(struct sha512_message *message);

//Sha512 Error Handling
/* When we call the function sha512_error, we will actually be calling a MACRO that will
	call the real function including the line number */
#define sha512_error(x) sha512_err(x, __FILE__, __func__, __LINE__)
void sha512_err(int error_code, const char *file_name, const char *function_name, unsigned int line){
	#define MALLOC_ERROR 1

	switch(error_code){
		case MALLOC_ERROR:
			fprintf(stderr, "[ERROR] (%s) Function %s at line %u: malloc() didn't work!\n", file_name, function_name, line);
			break;
		default:
			fprintf(stderr, "[ERROR] (%s) Function %s at line %u: Unknown error code!\n", file_name, function_name, line);
			break;
	}
}
/* We do the same to obtain a warning function */
#define sha512_warning(x) sha512_warn(x, __FILE__, __func__, __LINE__)
void sha512_warn(const char *warning_msg, const char *file_name, const char *function_name, unsigned int line){
	fprintf(stderr, "[WARNING] (%s) Function %s at line %u: %s\n", file_name, function_name, line, warning_msg);
}

//Sha512 Init
struct sha512_base *sha512_init(){
	struct sha512_base *base;

	base = malloc(sizeof(struct sha512_base));

	//Checks for error
	if(NULL == base){
		sha512_error(MALLOC_ERROR);
		goto ERROR;
	}

	//Initiates struct to 0
	memset(base, 0, sizeof(struct sha512_base));

	//Gets the hash values (First 32 bits of the fractional part of the square root from the first 8 prime numbers)
	static const uint32_t DefaultHashValues[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(base->HashValues, DefaultHashValues, sizeof(DefaultHashValues));	//Assign default values to the Structure
	//Gets the Round Constants (First 32 bits of the fractional part of the cube root from the first 64 prime numbers)
	static const uint32_t DefaultRoundConstants[64] = 
		{0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
	memcpy(base->RoundConstants, DefaultRoundConstants, sizeof(DefaultRoundConstants));

	//Messages linked list pointer initialization
	base->messages_list_entry.prev = NULL;
	base->messages_list_entry.next = NULL;

	return base;
ERROR:
	if(base){
		free(base);
	}
	return NULL;
}

//Sha512 Free
void sha512_free(struct sha512_base *base){
	//Frees the messages associated with the sha512 base struct
	while(base->messages_list_entry.next != NULL){
		struct sha512_message *entry;

		entry = base->messages_list_entry.next;

		sha512_message_delete(entry, base);
	}

	//Frees the sha512 base struct
	if(base){
		free(base);
	}
}

//Create a message to digest from a string
struct sha512_message *sha512_message_create_from_string(const char *string, struct sha512_base *base){
	struct sha512_message *message;

	message = malloc(sizeof(struct sha512_message));

	//Checks for error
	if(NULL == message){
		sha512_error(MALLOC_ERROR);
		goto ERROR;
	}

	//Adds the message to the linked list of messages
	//If it's the first message
	if(NULL == base->messages_list_entry.next){
		base->messages_list_entry.next = message;
		message->messages_list_entry.prev = base;
		message->messages_list_entry.next = NULL;
	} else {
		struct sha512_message *entry;
		//Get first message in the list
		entry = base->messages_list_entry.next;

		//While we are not in the last message
		while(entry->messages_list_entry.next != NULL){
			entry = entry->messages_list_entry.next;
		}

		//We are in the last message, add the new one
		entry->messages_list_entry.next = message;
		message->messages_list_entry.prev = entry;
		message->messages_list_entry.next = NULL;
	}

	return message;
ERROR:
	if(message){
		free(message);
	}
	return NULL;
}

//Deletes a sha512_message (-1 = error; 0 = OK)
int sha512_message_delete(struct sha512_message *message, struct sha512_base *base){
	if(NULL == base->messages_list_entry.next){
		sha512_warning("No messages to be removed.");
		return -1;	//No messages in the base
	} else {
		struct sha512_message *entry, *tmp_entry; //tmp_entry for conversing the void * to a struct sha512_message *
		//Get first message in the list
		entry = base->messages_list_entry.next;

		//Iterates through the entries looking for the one given (stops if the entry is found or
		//if we reach the end of the list)
		while((entry != message) && (NULL != entry)){
			entry = entry->messages_list_entry.next;
		}

		//The entry wasn't found
		if(NULL == entry){
			sha512_warning("Message wasn't found.");
			return -1;
		} else {
			//Removes the message and updates the linked list entries

			//Messages is right after the sha512_base entry:
			if(base == entry->messages_list_entry.prev){
				base->messages_list_entry.next = entry->messages_list_entry.next;
				if(entry->messages_list_entry.next != NULL){
					tmp_entry = entry->messages_list_entry.next;
					tmp_entry->messages_list_entry.prev = base;
				}

				free(entry);
				return 0;
			} else {
				if(entry->messages_list_entry.next != NULL){
					tmp_entry = entry->messages_list_entry.prev;
					tmp_entry->messages_list_entry.next = entry->messages_list_entry.next;

					tmp_entry = entry->messages_list_entry.next;
					tmp_entry->messages_list_entry.prev = entry->messages_list_entry.prev;
				} else {
					tmp_entry = entry->messages_list_entry.prev;
					tmp_entry->messages_list_entry.next = NULL;
				}

				free(entry);
				return 0;
			}
		}
	}
}

//Pre-processes the message:
/*
	Append bit '1' to the end of the message
	Append enough bits '0's to the message so the (resulting length in bits % 512 == 448)
	Append the length of the message (not including the '1' or '0' padding) in bits, as a 64-bit big-endian integer
*/
void sha512_message_preprocess(struct sha512_message *message) {

}
#endif
