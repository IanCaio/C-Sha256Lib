#include "sha512_digest.h"

int main(int argc, char **argv){
	struct sha512_base *handler = sha512_init();
	struct sha512_message *msg = sha512_message_create_from_string("STRING", handler);
	free(msg);
	sha512_free(handler);

	return 0;
}
