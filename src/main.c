#include "sha256_digest.h"

int main(int argc, char **argv){
	if(argc != 2){
		printf("[USAGE] ./bin/hash_me 'message to hash'\n");
		return 1;
	}

	struct sha256_base *handler = sha256_init();
	//Function won't include the null byte in the message
	struct sha256_message *msg = sha256_message_create_from_string(argv[1], handler);

	//Preprocess messages
	sha256_message_preprocess(msg);

	//Digest message
	sha256_message_digest(msg, handler);

	//Show hash
	sha256_message_show_hash(msg);

	//Delete the message (unnecessary since it's automatic on the sha256_free function)
	sha256_message_delete(msg, handler);

	sha256_free(handler);

	return 0;
}
