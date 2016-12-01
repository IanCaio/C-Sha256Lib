#include "sha512_digest.h"

int main(int argc, char **argv){
	struct sha512_base *handler = sha512_init();
	struct sha512_message *msg = sha512_message_create_from_string("STRING", handler);
	struct sha512_message *msg2 = sha512_message_create_from_string("STRING2", handler);

	//Parsing NULL to the function
	sha512_message_delete(NULL, handler);

	//Parsing an existing message to the function
	sha512_message_delete(msg, handler);

	//Parsing a deleted message to the function while the list isn't empty
	sha512_message_delete(msg, handler);

	//Parsing an existing message to the function
	sha512_message_delete(msg2, handler);

	//Parsing a message to delete when the list is empty
	sha512_message_delete(msg2, handler);

	sha512_free(handler);

	return 0;
}
