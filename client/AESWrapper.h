#pragma once

#include <string>


class AESWrapper
{
public:
	// AES key length in bytes updated to the maman requirement
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);
	AESWrapper& operator=(const AESWrapper& aes);
public:
	/*
	The GenerateKey and the empty constructor that calls it were deleted.
	The rdrand() function is not available on ARM processors.
	In addition, the loop in GenerateKey() jumps in 4 bytes, so if the key length is not a multiple of 4 it is a buffer overflow, and it is one of the weaknesses that we learn in the course.
	In addition, a failure in rdrand() is never checked, and in this case the key is predictable.
	The client doesn't need these functions since the server produces the AES key.
	*/

	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();

	const unsigned char* getKey() const;

	std::string encrypt(const char* plain, unsigned int length);
	std::string decrypt(const char* cipher, unsigned int length);
};