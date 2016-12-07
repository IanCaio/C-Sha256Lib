#include "sha256_digest.h"

int main(int argc, char **argv){
	if(argc != 2){
		printf("[USAGE] ./bin/test 'message to hash'\n");
		return 1;
	}

	struct sha256_base *handler = sha256_init();
	struct sha256_message *msg = sha256_message_create_from_buffer(argv[1], strlen(argv[1])*8, handler);
//	struct sha256_message *msg = sha256_message_create_from_string(argv[1], handler);

	//Preprocess messages
	sha256_message_preprocess(msg);

	sha256_message_show(msg);
	sha256_message_debug_bits(msg);

	//Digest messages
	sha256_message_digest(msg, handler);
	sha256_message_show_hash(msg);

	//Parsing an existing message to the function
	sha256_message_delete(msg, handler);

	sha256_free(handler);

	return 0;
}
