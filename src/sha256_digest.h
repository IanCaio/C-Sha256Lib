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

struct sha256_message{
	char *msg;
	uint64_t bits_length;
	char *preprocessed_msg;
	uint64_t preprocessed_bits_length;

	struct sha256_list messages_list_entry;
};

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

//Sha256 Error Handling
/* When we call the function sha256_error, we will actually be calling a MACRO that will
	call the real function including the line number */
#define sha256_error(x) sha256_err(x, __FILE__, __func__, __LINE__)
void sha256_err(int error_code, const char *file_name, const char *function_name, unsigned int line){
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
#define sha256_warning(x) sha256_warn(x, __FILE__, __func__, __LINE__)
void sha256_warn(const char *warning_msg, const char *file_name, const char *function_name, unsigned int line){
	fprintf(stderr, "[WARNING] (%s) Function %s at line %u: %s\n", file_name, function_name, line, warning_msg);
}

//Sha256 Init
struct sha256_base *sha256_init(){
	struct sha256_base *base;

	base = malloc(sizeof(struct sha256_base));

	//Checks for error
	if(NULL == base){
		sha256_error(MALLOC_ERROR);
		goto ERROR;
	}

	//Initiates struct to 0
	memset(base, 0, sizeof(struct sha256_base));

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

//Sha256 Free
void sha256_free(struct sha256_base *base){
	//Frees the messages associated with the sha256 base struct
	while(base->messages_list_entry.next != NULL){
		struct sha256_message *entry;

		entry = base->messages_list_entry.next;

		sha256_message_delete(entry, base);
	}

	//Frees the sha256 base struct
	if(base){
		free(base);
	}
}

//Create a message to digest from a string
struct sha256_message *sha256_message_create_from_string(const char *string, struct sha256_base *base){
	struct sha256_message *message;

	message = malloc(sizeof(struct sha256_message));

	//Checks for error
	if(NULL == message){
		sha256_error(MALLOC_ERROR);
		goto ERROR1;
	}

	//Initialize with 0's
	memset(message, 0, sizeof(struct sha256_message));

	//Adds the message to the linked list of messages
	//If it's the first message
	if(NULL == base->messages_list_entry.next){
		base->messages_list_entry.next = message;
		message->messages_list_entry.prev = base;
		message->messages_list_entry.next = NULL;
	} else {
		struct sha256_message *entry;
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

	//Allocates space for the message string (String + null byte)
	message->msg = malloc(strlen(string) + 1);

	if(NULL == message->msg){
		sha256_error(MALLOC_ERROR);
		goto ERROR2;
	}

	//BE VERY AWARE! We allocated enough space to hold the string in line 180, but be careful when
	//using strcpy().
	strcpy(message->msg, string);

	//Update the bit_length field (number of bytes * 8 bits/byte)
	//(strlen + '\0') * 8 bits/byte
	message->bits_length = (strlen(message->msg) + 1) * 8;

	return message;

ERROR1:	//sha256_message struct allocation error
	if(message){
		free(message);
	}
	return NULL;
ERROR2:	//sha256_message->msg string allocation error
	if(message->msg){
		free(message->msg);
	}
	//We call the sha256_message_delete function to avoid having to worry about the linked list updating
	if(message){
		sha256_message_delete(message, base);
	}
	return NULL;
}

//Print the sha256_message string
void sha256_message_show(struct sha256_message *message){
	printf("Message:\n");
	printf("'%s'\n", message->msg);
	printf("Length: %lu bits\n", (long unsigned int) message->bits_length);
}

//Print the sha256_message msg and preprocessed_msg in binary notation for debugging
void sha256_message_debug_bits(struct sha256_message *message){
	printf("Message %lu bits:\n", (long unsigned int) message->bits_length);

	int counter;
	unsigned char z;

	//MSG
	for(counter = 0; counter < (message->bits_length/8); ++counter){
		for(z = 128; z > 0; z >>= 1){
			if((message->msg[counter] & z) == z){
				printf("1");
			} else {
				printf("0");
			}
		}

		//Just make the output a little more readable (lines of 10 bytes)
		if(0 == (counter+1) % 10){
			printf("\n");
		} else {
			printf(" "); //Space between each byte
		}
	}

	printf("\n");

	//PREPROCESSED MSG
	printf("Preprocessed message %lu bits:\n", (long unsigned int) message->preprocessed_bits_length);

	for(counter = 0; counter < (message->preprocessed_bits_length/8); ++counter){
		for(z = 128; z > 0; z >>= 1){
			if((message->preprocessed_msg[counter] & z) == z){
				printf("1");
			} else {
				printf("0");
			}
		}

		//Just make the output a little more readable (lines of 10 bytes)
		if(0 == (counter+1) % 10){
			printf("\n");
		} else {
			printf(" "); //Space between each byte
		}
	}

	printf("\n");
}

//Deletes a sha256_message (-1 = error; 0 = OK)
int sha256_message_delete(struct sha256_message *message, struct sha256_base *base){
	if(NULL == base->messages_list_entry.next){
		sha256_warning("No messages to be removed.");
		return -1;	//No messages in the base
	} else {
		struct sha256_message *entry, *tmp_entry; //tmp_entry for conversing the void * to a struct sha256_message *
		//Get first message in the list
		entry = base->messages_list_entry.next;

		//Iterates through the entries looking for the one given (stops if the entry is found or
		//if we reach the end of the list)
		while((entry != message) && (NULL != entry)){
			entry = entry->messages_list_entry.next;
		}

		//The entry wasn't found
		if(NULL == entry){
			sha256_warning("Message wasn't found.");
			return -1;
		} else {
			//Removes the message and updates the linked list entries
			//Messages is right after the sha256_base entry:
			if(base == entry->messages_list_entry.prev){
				base->messages_list_entry.next = entry->messages_list_entry.next;
				if(entry->messages_list_entry.next != NULL){
					tmp_entry = entry->messages_list_entry.next;
					tmp_entry->messages_list_entry.prev = base;
				}
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
			}

			//Free everything on the message entry
			if(entry->msg){
				free(entry->msg);
			}
			if(entry->preprocessed_msg){
				free(entry->preprocessed_msg);
			}
			free(entry);
			return 0;
		}
	}
}

//Two functions to check if the variables are being stored in big-endian or little-endian
int sha256_big_endian(void){
	int test = 1;
	char *z = (char *) &test;

	if(*z == 1){
		return 0;
	} else {
		return 1;
	}
}
int sha256_little_endian(void){
	int test = 1;
	char *z = (char *) &test;

	if(*z == 1){
		return 1;
	} else {
		return 0;
	}
}

//Pre-processes the message:
/*
	Append bit '1' to the end of the message
	Append enough bits '0's to the message so the (resulting length in bits % 512 == 448)
	Append the length of the message (not including the '1' or '0' padding) in bits, as a 64-bit big-endian integer
*/
//Returns 0 if it went OK, -1 if any error occurred
int sha256_message_preprocess(struct sha256_message *message) {
	//How much memory will we need for the preprocessed message?
	//message + 1 bit + 64 bits
	if( (message->bits_length + 65) % 512 ){
		message->preprocessed_bits_length = ((message->bits_length + 65)/512 + 1)*512;
	} else {
		message->preprocessed_bits_length = (message->bits_length + 65);
	}

	//Allocating the preprocessed_msg memory
	//preprocessed_bits_length will always be divisable by 8, since it will be a multiple of 512
	message->preprocessed_msg = malloc((size_t) (message->preprocessed_bits_length/8));

	//Error handling
	if(NULL == message->preprocessed_msg){
		sha256_error(MALLOC_ERROR);
		return -1;
	}

	//Initialize with 0's
	memset(message->preprocessed_msg, 0, (size_t) (message->preprocessed_bits_length/8));

	//Copy the original message to the preprocessed one
	//BE AWARE: We are allocating enough space for holding the msg in the line 328, but be careful with memcpy!
	//The following 'if' is to support empty messages
	if(message->bits_length > 0){
		//The following 'if' is to support the future possible feature of being able to hash messages that have
		//a bit length not divisable by 8 (broken bytes), like '01101' or '01100111 1101' for example.
		if(0 == message->bits_length % 8){
			memcpy(message->preprocessed_msg, message->msg, (size_t) (message->bits_length/8));
		} else {
			memcpy(message->preprocessed_msg, message->msg, (size_t) ((message->bits_length/8) + 1));
		}
	}

	//Now we append the '1' bit
	//The position is exactly the bit length (counting 0 as the first position)
	uint64_t append_position = message->bits_length;
	//Now we find the byte in the preprocessed message holding the bit to be turned on
	uint64_t append_byte = (append_position/8);

	//Switch the bit on
	message->preprocessed_msg[append_byte] |= (1 << (7 - append_position % 8));

	//Append the 64-bit message size in the end (big-endian)
	uint64_t size_byte_pos = message->preprocessed_bits_length/8 - 8;
	if(sha256_big_endian()){
		//  ______________________________________________________
		// | byte 0 | byte 1 | ... | byte n-2 | byte n-1 | byte n |
		// |________|________|_____|__________|__________|________|
		//
		// n = (message->preprocessed_bits_length-1/8)
		// if message->preprocessed_bits_length == 0 we have a malformed message (ERROR)
		memcpy(&message->preprocessed_msg[size_byte_pos], &message->bits_length, sizeof(uint64_t));
	} else {
		uint8_t *byte_pointer = (uint8_t *) &message->bits_length;

		uint64_t current_byte = (message->preprocessed_bits_length-1)/8;

		for(; current_byte >= size_byte_pos; --current_byte){
			memcpy(&message->preprocessed_msg[current_byte], byte_pointer, sizeof(uint8_t));
			++byte_pointer;
		}
	}
}

#endif
