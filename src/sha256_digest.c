#include "sha256_digest.h"

//Sha256 Error Handling
/* When we call the function sha256_error, we will actually be calling a MACRO that will
	call the real function including the line number */
#define sha256_error(x) sha256_err(x, __FILE__, __func__, __LINE__)
void sha256_err(int error_code, const char *file_name, const char *function_name, unsigned int line){
	#define MALLOC_ERROR 1
	#define DIGEST_ERROR 2

	switch(error_code){
		case MALLOC_ERROR:
			fprintf(stderr, "[ERROR] (%s) Function %s at line %u: malloc() didn't work!\n", file_name, function_name, line);
			break;
		case DIGEST_ERROR:
			fprintf(stderr, "[ERROR] (%s) Function %s at line %u: Trying to digest a message that wasn't pre-processed!\n", file_name, function_name, line);
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
struct sha256_base *sha256_init(void){
	struct sha256_base *base;

	base = malloc(sizeof(struct sha256_base));

	//Checks for error
	if(NULL == base){
		sha256_error(MALLOC_ERROR);
		goto error1;
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
error1:
	if(base){
		free(base);
	}
	return NULL;
}

//Sha256 Free
void sha256_free(struct sha256_base *base){
	//Frees the messages associated with the sha256 base struct
	while(NULL != base->messages_list_entry.next){
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
		goto error1;
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
		while(NULL != entry->messages_list_entry.next){
			entry = entry->messages_list_entry.next;
		}

		//We are in the last message, add the new one
		entry->messages_list_entry.next = message;
		message->messages_list_entry.prev = entry;
		message->messages_list_entry.next = NULL;
	}

	//Allocates space for the message string (without the null byte)
	message->msg = malloc(strlen(string));

	if(NULL == message->msg){
		sha256_error(MALLOC_ERROR);
		goto error2;
	}

	//BE VERY AWARE! We allocated enough space to hold the string in line 128 (without null byte), but be careful when
	//using memcpy().
	memcpy(message->msg, string, strlen(string));

	//Update the bit_length field (number of bytes * 8 bits/byte)
	//(strlen + '\0') * 8 bits/byte
	message->bits_length = (strlen(string)) * 8;

	message->digested = 0; //Message is not digested yet (Just explicitly stating it, though we already
				//initialized the object to 0...)
	message->processed = 0; //Message is not processed yet (Just explicitly stating it, though we already
				//initialized the object to 0...)

	return message;

error1:	//sha256_message struct allocation error
	if(message){
		free(message);
	}
	return NULL;
error2:	//sha256_message->msg string allocation error
	if(message->msg){
		free(message->msg);
	}
	//We call the sha256_message_delete function to avoid having to worry about the linked list updating
	if(message){
		sha256_message_delete(message, base);
	}
	return NULL;
}

//Create message from a buffer, specifying the length of the message. That way the user can create a message
//that has a length outside the bytes boundaries (not a multiple of 8 bits).
struct sha256_message *sha256_message_create_from_buffer(const char *buffer, unsigned int bits_length, struct sha256_base *base){
	struct sha256_message *message;

	message = malloc(sizeof(struct sha256_message));

	//Checks for error
	if(NULL == message){
		sha256_error(MALLOC_ERROR);
		goto error1;
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
		while(NULL != entry->messages_list_entry.next){
			entry = entry->messages_list_entry.next;
		}

		//We are in the last message, add the new one
		entry->messages_list_entry.next = message;
		message->messages_list_entry.prev = entry;
		message->messages_list_entry.next = NULL;
	}

	//Size of the message:
	//If the message size is 0 bits, we allocate at least a byte to hold the message.
	//Else, we check how many bytes we need to hold the complete message.
	size_t message_size;
	if(0 == bits_length){
		message_size = 1;
	} else {
		message_size = bits_length/8;
		if(bits_length%8){
			++message_size; //If we extrapolate the byte boundary, add another byte.
		}
	}

	message->msg = malloc(message_size);

	//Fill with 0's
	memset(message->msg, 0, message_size);

	if(NULL == message->msg){
		sha256_error(MALLOC_ERROR);
		goto error2;
	}

	//The user is responsable for giving a length of bits that doesn't extrapolate the buffer size.
	//If the user gives us a buffer, smaller then the bits_length given we will end up accessing
	//out-of-boundary memory!
	if(bits_length > 0){
		memcpy(message->msg, buffer, message_size);
	}

	//Remove the extra bits that could possibly be copied to the message buffer
	if(bits_length%8){
		unsigned char mask_byte = 0;
		for(unsigned int c = 0; c < (8 - bits_length%8); ++c){
			mask_byte = mask_byte*2 + 1;
		}
		mask_byte = ~mask_byte;

		message->msg[message_size-1] = message->msg[message_size-1] & mask_byte;
	}

	//Update the bit_length field
	message->bits_length = bits_length;

	message->digested = 0; //Message is not digested yet (Just explicitly stating it, though we already
				//initialized the object to 0...)
	message->processed = 0; //Message is not processed yet (Just explicitly stating it, though we already
				//initialized the object to 0...)

	return message;

error1:	//sha256_message struct allocation error
	if(message){
		free(message);
	}
	return NULL;
error2:	//sha256_message->msg string allocation error
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
	puts("======================================");
	puts("Message:");
	int message_size;
	if(0 == message->bits_length){
		message_size = 1;
	} else {
		message_size = message->bits_length/8;
		if(message->bits_length % 8){
			++message_size;
		}
	}
	printf("'");
	for(int c = 0; c < message_size; ++c){
		printf("%c", message->msg[c]);
	}
	puts("'");
	printf("Length: %lu bits.\n", (long unsigned int) message->bits_length);
	puts("======================================");
}

//Print the sha256_message msg and preprocessed_msg in binary notation for debugging
void sha256_message_debug_bits(struct sha256_message *message){
	if(0 == message->processed){
		puts("Message not pre-processed.");
		sha256_warning("Message wasn't pre-processed yet.");
	} else {
		puts("======================================");
		printf("Message (%lu bits):\n", (long unsigned int) message->bits_length);

		unsigned int counter;
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
				puts("");
			} else {
				printf(" "); //Space between each byte
			}
		}

		puts("");

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
				puts("");
			} else {
				printf(" "); //Space between each byte
			}
		}

		puts("");
		puts("======================================");
	}
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
				if(NULL != entry->messages_list_entry.next){
					tmp_entry = entry->messages_list_entry.next;
					tmp_entry->messages_list_entry.prev = base;
				}
			} else {
				if(NULL != entry->messages_list_entry.next){
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

//Pre-processes the message:
/*
	Append bit '1' to the end of the message
	Append enough bits '0's to the message so the (resulting length in bits % 512 == 448)
	Append the length of the message (not including the '1' or '0' padding) in bits, as a 64-bit big-endian integer
*/
//Returns 0 if it went OK, -1 if any error occurred
int sha256_message_preprocess(struct sha256_message *message) {
	if(message->processed){
		sha256_warning("Trying to pre-process a message already processed.");
		return 0;
	} else {
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

		message->preprocessed_msg[size_byte_pos] = (message->bits_length >> 56) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 1] = (message->bits_length >> 48) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 2] = (message->bits_length >> 40) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 3] = (message->bits_length >> 32) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 4] = (message->bits_length >> 24) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 5] = (message->bits_length >> 16) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 6] = (message->bits_length >> 8) & 0xFF;
		message->preprocessed_msg[size_byte_pos + 7] = message->bits_length & 0xFF;

		message->processed = 1;

		return 0;
	}
}

//LOGICAL FUNCTIONS:
//Ch(x,y,z)
uint32_t sha256_logical_func1(uint32_t x, uint32_t y, uint32_t z){
	uint32_t result = (x & y) ^ ((~x) & z);
	return result;
}
//Maj(x,y,z)
uint32_t sha256_logical_func2(uint32_t x, uint32_t y, uint32_t z){
	uint32_t result = (x & y) ^ (x & z) ^ (y & z);
	return result;
}
//Sigma0(x)
uint32_t sha256_logical_func3(uint32_t x){
	uint32_t result = RIGHTROTATE_32(x, 2) ^ RIGHTROTATE_32(x, 13) ^ RIGHTROTATE_32(x, 22);
	return result;
}
//Sigma1(x)
uint32_t sha256_logical_func4(uint32_t x){
	uint32_t result = RIGHTROTATE_32(x, 6) ^ RIGHTROTATE_32(x, 11) ^ RIGHTROTATE_32(x, 25);
	return result;
}
//LowSigma0(x)
uint32_t sha256_logical_func5(uint32_t x){
	uint32_t result = RIGHTROTATE_32(x, 7) ^ RIGHTROTATE_32(x, 18) ^ (x >> 3);
	return result;
}
//LowSigma1(x)
uint32_t sha256_logical_func6(uint32_t x){
	uint32_t result = RIGHTROTATE_32(x, 17) ^ RIGHTROTATE_32(x, 19) ^ (x >> 10);
	return result;
}

//Digest function
void sha256_message_digest(struct sha256_message *message, struct sha256_base *base){
	if(0 == message->processed){
		sha256_error(DIGEST_ERROR);
		return;
	} else if(message->digested){
		sha256_warning("Message already digested.");
		return;
	} else {
		//Initialize current hash values
		uint32_t digest_hash_values[8];

		for(int c = 0; c < 8; ++c){
			digest_hash_values[c] = base->HashValues[c];
		}

		//Message will be divided into 512 bit chunks
		unsigned int number_of_chunks = message->preprocessed_bits_length/512;

		//For each chunk
		for(unsigned int chunk = 0; chunk < number_of_chunks; ++chunk){
			unsigned char *chunk_pointer;
			chunk_pointer = message->preprocessed_msg;
			chunk_pointer += chunk*64; //64 bytes per chunk (512 bits)

			uint32_t message_schedule[64];

			//Copy the 32-bit pieces of the chunk in the message schedule little-endian (so we can use the processor
			//arithmetics on it), or keep it big endian if the processor works with big endian memory layout.
			unsigned char *message_byte = chunk_pointer;
			for(int j = 0; j < 16; ++j){
				message_schedule[j] = (((uint32_t) *(message_byte + 3)) << 0) | (((uint32_t) *(message_byte + 2)) << 8) | (((uint32_t) *(message_byte + 1)) << 16) | (((uint32_t) *(message_byte)) << 24);
				message_byte += 4; //Advance 4 bytes
			}

			//Expand the message blocks:
			for(int j = 16; j < 64; ++j){
				message_schedule[j] = sha256_logical_func6(message_schedule[j-2]) + message_schedule[j-7]
					+ sha256_logical_func5(message_schedule[j-15]) + message_schedule[j-16];
			}

			uint32_t chunk_hash_values[8];

			for(int n = 0; n < 8; ++n){
				chunk_hash_values[n] = digest_hash_values[n];
			}

			//Work the chunk hash values
			for(int j = 0; j < 64; ++j){
				uint32_t tmp1, tmp2;

				tmp1 = chunk_hash_values[7] + sha256_logical_func4(chunk_hash_values[4])
					+ sha256_logical_func1(chunk_hash_values[4], chunk_hash_values[5], chunk_hash_values[6])
					+ base->RoundConstants[j] + message_schedule[j];
				tmp2 = sha256_logical_func3(chunk_hash_values[0])
					+ sha256_logical_func2(chunk_hash_values[0], chunk_hash_values[1], chunk_hash_values[2]);

				chunk_hash_values[7] = chunk_hash_values[6];
				chunk_hash_values[6] = chunk_hash_values[5];
				chunk_hash_values[5] = chunk_hash_values[4];
				chunk_hash_values[4] = chunk_hash_values[3] + tmp1;
				chunk_hash_values[3] = chunk_hash_values[2];
				chunk_hash_values[2] = chunk_hash_values[1];
				chunk_hash_values[1] = chunk_hash_values[0];
				chunk_hash_values[0] = tmp1 + tmp2;
			}

			for(int n = 0; n < 8; ++n){
				digest_hash_values[n] += chunk_hash_values[n];
			}
		}

		//Copy the hash reversing the endianness of each 32-bit piece, since we used
		//little-endian and the algorithm requires big-endian values. Doesn't reverse the
		//order if we are already using big-endian.
		for(int i = 0, hashindex = 0; i < 8; ++i){
			message->hash[hashindex] = (digest_hash_values[i] >> 24) & 0xFF;
			message->hash[hashindex+1] = (digest_hash_values[i] >> 16) & 0xFF;
			message->hash[hashindex+2] = (digest_hash_values[i] >> 8) & 0xFF;
			message->hash[hashindex+3] = digest_hash_values[i] & 0xFF;
			hashindex += 4;
		}

		message->digested = 1;
	}
}

//Print the hash in the screen in hexadecimal
void sha256_message_show_hash(struct sha256_message *message){
	if(message->digested){
		printf("HASH: ");
		for(int c = 0; c < 32; ++c){
			printf("%02X", (unsigned int) message->hash[c]);
		}
		printf("\n");
		printf("CHARS: ");
		for(int c = 0; c < 32; ++c){
			printf("%c", message->hash[c]);
		}
		puts("");
	} else {
		puts("Message not digested.");
		sha256_warning("Trying to show a hash of a message not yet digested.");
	}
}

//Allocates a string that will hold the hash hexadecimal representation and a null terminator
//returning the pointer to it. It's the users responsability to free the message after using
//it with free();
//The string will be returned with the hexadecimal representation in lower case letters.
char *sha256_message_get_hash(struct sha256_message *message){
	char *returned_hash = malloc(65); //64 characters + null terminator

	if(NULL == returned_hash){
		sha256_error(MALLOC_ERROR);
		return NULL;
	} else {
		for(int c = 0; c < 32; ++c){
			//We use 3 as the size since if we use 2, the snprintf will "sacrifice" the last character
			//to keep space for the null terminator. We will end up overwriting the null terminator of
			//every iteration with the 2 characters of the next one. The last write will write up to the
			//index 64 (c = 31 -> c*2 = 62 -> 62, 63, 64). The null byte will be in the last position, so we
			//don't need to explicitly write it after the iterations. The string will already be null-terminated.
			snprintf(&returned_hash[c*2], (size_t) 3, "%02x", (unsigned int) message->hash[c]);
		}

		return returned_hash;
	}
}

