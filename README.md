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

	struct sha256_message *sha256_message_create_from_buffer(const char *buffer, int bits_length, struct sha256_base *handler);

		This function returns a sha256_message structure created from a buffer with the speficified bits
		length. This way, the user is free to create a message that doesn't fit bytes boundaries. It's
		theoretically possible to digest a message with 5 bits of length, for example, but most implementations
		will fetch the message from a string (or a file) which are usually inside the byte boundaries.
		By giving a buffer containing the message and specifying a length, the function will zero-out the
		extra bits and create a structure with the message (inside enough bytes to hold it) and with the
		right value on the bits_length field.
		ATENTION: The user is responsable for respecting the buffer boundaries when calling this function!
		i.e.: If the user allocates 4 bytes for the buffer and calls this function specifying a bits_length
		of 35 bits, the program will try to copy memory from the 5th byte. This can result in undefined
		behaviour and hard to track bugs in the program.

	int sha256_message_delete(struct sha256_message *msg, struct sha256_base *handler);

		This function will delete the sha256_message parsed if it is present in the handler's linked list.
		It will return 0 if all went fine and -1 if anything odd happened. If a message that isn't present
		in the handler's list is parsed or if the handler'd linked list is empty, a warning will be written
		to STDERR stating so and the function will return -1.
		The user should be aware that unless there are restrictions on the memory usage and the number of
		messages during the session can reach high numbers, this function isn't necessary, since the messages
		will be free'd upon sha256_free() call. Deleting messages that could be digested again later will also
		cause the hash processing to be called again (no cached result).

	int sha256_message_preprocess(struct sha256_message *msg);

		This function will preprocess the message and store the result in a variable in the sha256_message
		structure. This preprocessing consists of:
			-Appending a '1' bit right after the original message
			-Padding '0's to the preprocessed message until there's only 64 bits available before the
		size of the preprocessed message is a multiple of 512.
			-Append the original message bits length as a big-endian 64-bit integer to the end of the
		preprocessed message.
		ATTENTION: If the message was already preprocessed a warning will be sent to stderr stating that
		the user is trying to preprocess a message that was already processed and return 0. It will only
		return -1 if the function runs in some memory allocation issues.

	void sha256_message_digest(struct sha256_message *msg, struct sha256_base *handler);

		This function will digest the message and store the hash in the msg->hash field of the sha256_message
		object.
		The function uses some internal logical functions described in the sha256 specification.
		ATTENTION: An error is prompted to stderr if the user tries to digest a message that wasn't preprocessed.
		An warning is prompted to stderr if the user tries to digest a message already digested (it isn't an
		error and the user can just access the hash processed before, so it's really just a warning).

	void sha256_message_show_hash(struct sha256_message *msg);

		This function prints the hash of the message to stdout in the following format:
		"HASH: <hash in hexadecimal-uppercase>"
		"CHARS: <hash in ASCII>"
		The latter is pretty much useless since many characters from the hash are probably not printable.

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

	void sha256_message_show(struct sha256_message *msg);

		This function prints the message content as a string on the screen.

	void sha256_message_debug_bits(struct sha256_message *msg);

		This function will print the bits from both the message and the preprocessed message to the screen for
		debugging purposes.

	int sha256_big_endian(void);

		Returns 1 if the memory layout is big endian, 0 if it's not (little endian).

	int sha256_little_endian(void);

		Returns 1 if the memory layout is little endian, 0 if it's not (big endian).

	uint32_t sha256_logical_func1(uint32_t x, uint32_t y, uint32_t z);
	uint32_t sha256_logical_func2(uint32_t x, uint32_t y, uint32_t z);
	uint32_t sha256_logical_func3(uint32_t x);
	uint32_t sha256_logical_func4(uint32_t x);
	uint32_t sha256_logical_func5(uint32_t x);
	uint32_t sha256_logical_func6(uint32_t x);

		Logical functions used by the sha256_message_digest() function described in the sha256 specification.
