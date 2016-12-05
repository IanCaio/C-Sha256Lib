#include "sha256_digest.h"

int main(int argc, char **argv){
	struct sha256_base *handler = sha256_init();
	struct sha256_message *msg = sha256_message_create_from_string("", handler);
	struct sha256_message *msg2 = sha256_message_create_from_string("a string!", handler);
	char buffer[] = "";
	buffer[0] = 255;
	struct sha256_message *msg3 = sha256_message_create_from_buffer(buffer, 5, handler);

	//Preprocess messages
	sha256_message_preprocess(msg);
	sha256_message_preprocess(msg2);
	sha256_message_preprocess(msg3);

	//Show messages bits
	sha256_message_debug_bits(msg);
	sha256_message_debug_bits(msg2);
	sha256_message_debug_bits(msg3);

	//Show messages content
	sha256_message_show(msg);
	sha256_message_show(msg2);
	sha256_message_show(msg3);

	//Parsing NULL to the function
	sha256_message_delete(NULL, handler);

	//Parsing an existing message to the function
	sha256_message_delete(msg, handler);

	//Parsing a deleted message to the function while the list isn't empty
	sha256_message_delete(msg, handler);

	//Parsing an existing message to the function
	sha256_message_delete(msg2, handler);

	//Parsing a message to delete when the list is empty
	sha256_message_delete(msg2, handler);

	sha256_free(handler);

	return 0;
}
