Sha256 Digest Library

###DOCUMENTATION

	struct sha256_base *sha256_init();

		This function returns a handler to a sha256_base struct. This structure has some constants
		and variables necessary to the hash algorithm processing. After creating a sha256_base handler,
		the user is free to create messages to be digested. After freeing the sha256_base handler, all
		messages associated with it will also be free'd.

	void sha256_free(struct sha256_base *handler);

		This function frees the memory allocated by the handler and all the messages associated with it
		that weren't manually free'd.

	struct sha256_message *sha256_message_create_from_string(const char *string, struct sha256_base *handler);

		This function returns a sha256_message structure created from a string. This structure can later be
		processed by the digest function to obtain a SHA256 hash. This hash will be stored in the structure
		in case the user decides to digest the same message again (no unnecessary processing).
		The sha256_message will be associated with the handler parsed in the function, so freeing it is not
		required since the sha256_free() function will free all memory allocated associated with this handler.

	int sha256_message_delete(struct sha256_message *msg, struct sha256_base *handler);

		This function will delete the sha256_message parsed if it is present in the handler's linked list.
		It will return 0 if all went fine and -1 if anything odd happened. If a message that isn't present
		in the handler's list is parsed or if the handler'd linked list is empty, a warning will be written
		to STDERR stating so and the function will return -1.
		The user should be aware that unless there are restrictions on the memory usage and the number of
		messages during the session can reach high numbers, this function isn't necessary, since the messages
		will be free'd upon sha256_free() call. Deleting messages that could be digested again later will also
		cause the hash processing to be called again (no cached result).

###INTERNAL FUNCTIONS

	MACRO:
	#define sha256_error(x) sha256_err(x, __FILE__, __func__, __LINE__)
	void sha256_err(int error_code, const char *file_name, const char *function_name, unsigned int line);

		This function isn't called directly. It's called through the MACRO sha256_error, that will take care
		of including the file name, function name and line, requiring only the error code. Inside the function
		there are some MACROs assigning some integers to some specific errors, so the user can write a more
		readable description of the error in the function call.
		Error Codes:
			MALLOC_ERROR = 1
				This error code should be used to prompt a message regarding the malloc() function
				returning a NULL value.

		The user should be aware (in case he intends to use this function, which I don't advise), that this
		function holds no responsability on taking actions in the case of an error. It only displays an error
		message and returns control to the calling code.

	MACRO:
	#define sha256_warning(x) sha256_warn(x, __FILE__, __func__, __LINE__)
	void sha256_warn(const char *warning_msg, const char *file_name, const char *function_name, unsigned int line);

		This function works similarly to the sha256_error macro/sha256_err function. Instead of receiving an
		error code though, it receives a message that will be displayed as a warning.
