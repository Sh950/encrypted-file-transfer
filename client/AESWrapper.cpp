#include "AESWrapper.h"

#include <modes.h>
#include <aes.h>
#include <filters.h>

#include <stdexcept>
#include <string>
#include <misc.h>   




AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (key == nullptr)
		throw std::invalid_argument("AES key is null");
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 32 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

AESWrapper::~AESWrapper()
{
	CryptoPP::SecureWipeArray(_key, DEFAULT_KEYLENGTH);
}

const unsigned char* AESWrapper::getKey() const 
{ 
	return _key; 
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	if (plain == nullptr && length > 0)
		throw std::invalid_argument("AES encrypt: null input");
	
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	// CBC ciphertext with PKCS#7 padding is always a positive multiple of the block size
	if (cipher == nullptr || length == 0 || length % CryptoPP::AES::BLOCKSIZE != 0)
		throw std::invalid_argument("AES decrypt: invalid ciphertext length");
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}
