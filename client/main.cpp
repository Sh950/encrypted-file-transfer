#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include "Endian.h"
#include <vector>
#include <stdexcept>

void hexify(const unsigned char* buffer, unsigned int length)
{
	std::ios::fmtflags f(std::cout.flags());
	std::cout << std::hex;
	for (size_t i = 0; i < length; i++)
		std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
	std::cout << std::endl;
	std::cout.flags(f);
}


int aes_example()
{
	std::cout << std::endl << std::endl << "----- AES EXAMPLE -----" << std::endl << std::endl;

	std::string plaintext = "Once upon a time, a plain text dreamed to become a cipher";
	std::cout << "Plain:" << std::endl << plaintext << std::endl;

	// 1. Initialize AESWrapper with a fixed test key (GenerateKey was removed ).
	unsigned char key[AESWrapper::DEFAULT_KEYLENGTH];
	for (unsigned int i = 0; i < AESWrapper::DEFAULT_KEYLENGTH; i++)
		key[i] = static_cast<unsigned char>(i);	// fixed test key
	AESWrapper aes(key, AESWrapper::DEFAULT_KEYLENGTH);

	try {
		AESWrapper bad(key, 16);
		std::cout << "FAIL: 16-byte key accepted" << std::endl;
	}
	catch (const std::length_error&) {
		std::cout << "OK: 16-byte key rejected" << std::endl;
	}

	// 2. encrypt a message (plain text)
	std::string ciphertext = aes.encrypt(plaintext.c_str(), plaintext.length());
	std::cout << "Cipher:" << std::endl;
	hexify(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());	// print binary data nicely

	// 3. decrypt a message (cipher text)
	std::string decrypttext = aes.decrypt(ciphertext.c_str(), ciphertext.length());
	std::cout << "Decrypted:" << std::endl << decrypttext << std::endl;

	return 0;
}


int rsa_example()
{
	std::cout << std::endl << std::endl << "----- RSA EXAMPLE -----" << std::endl << std::endl;

	// plain text (could be binary data as well)
	unsigned char plain[] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
	std::cout << "plain:" << std::endl;
	hexify(plain, sizeof(plain));		// print binary data nicely

	// 1. Create an RSA decryptor. this is done here to generate a new private/public key pair
	RSAPrivateWrapper rsapriv;

	// 2. get the public key
	std::string pubkey = rsapriv.getPublicKey();	// you can get it as std::string ...
	std::cout << "Public key size: " << pubkey.size() << " (expected 160)" << std::endl;
	
	char pubkeybuff[RSAPublicWrapper::KEYSIZE]; 
	rsapriv.getPublicKey(pubkeybuff, RSAPublicWrapper::KEYSIZE);	// ...or as a char* buffer

	// 3. create an RSA encryptor
	RSAPublicWrapper rsapub(pubkey);
	std::string cipher = rsapub.encrypt((const char*)plain, sizeof(plain));	// you can encrypt a const char* or an std::string 
	std::cout << "cipher:" << std::endl;
	hexify((unsigned char*)cipher.c_str(), cipher.length());	// print binary data nicely


	// 4. get the private key and encode it as base64 (base64 in not necessary for an RSA decryptor.)
	std::string base64key = Base64Wrapper::encode(rsapriv.getPrivateKey());
	std::cout << "Newlines in base64: " << std::count(base64key.begin(), base64key.end(), '\n') << " (expected 0)" << std::endl;   

	// 5. create another RSA decryptor using an existing private key (decode the base64 key to an std::string first)
	RSAPrivateWrapper rsapriv_other(Base64Wrapper::decode(base64key));

	std::string decrypted = rsapriv_other.decrypt(cipher);		// 6. you can decrypt an std::string or a const char* buffer
	std::cout << "decrypted:" << std::endl;
	hexify((unsigned char*)decrypted.c_str(), decrypted.length());	// print binary data nicely

	return 0;
}

// Prints OK/FAIL for one check, so each result is visible on its own line.
void check(const char* name, bool passed)
{
	std::cout << (passed ? "OK   " : "FAIL ") << name << std::endl;
}

int endian_test()
{
	std::cout << std::endl << std::endl << "----- ENDIAN TEST -----" << std::endl << std::endl;

	// 1. Known values - computed by hand earlier
	std::vector<uint8_t> buf16;
	appendU16(buf16, 825);
	check("appendU16(825) == 39 03", buf16 == std::vector<uint8_t>{ 0x39, 0x03 });
	hexify(buf16.data(), static_cast<unsigned int>(buf16.size()));

	std::vector<uint8_t> buf32;
	appendU32(buf32, 415);
	check("appendU32(415) == 9F 01 00 00", buf32 == std::vector<uint8_t>{ 0x9F, 0x01, 0x00, 0x00 });
	hexify(buf32.data(), static_cast<unsigned int>(buf32.size()));

	// 2. Round trip - read back what was written
	check("readU16 round trip == 825", readU16(buf16, 0) == 825);
	check("readU32 round trip == 415", readU32(buf32, 0) == 415);

	// 3. High byte >= 0x80 - the case where the sign bit matters in readU32
	std::vector<uint8_t> bufHigh;
	appendU32(bufHigh, 0x80000001);
	check("readU32 round trip == 0x80000001", readU32(bufHigh, 0) == 0x80000001);

	// 4. Bounds - reading past the end must throw, not read garbage
	std::vector<uint8_t> shortBuf{ 0x01, 0x02, 0x03 };
	try {
		readU32(shortBuf, 0);
		check("readU32 on 3 bytes throws", false);
	}
	catch (const std::out_of_range&) {
		check("readU32 on 3 bytes throws", true);
	}

	// 5. Huge offset - the overflow case: offset + n would wrap around to a small number
	try {
		readU16(shortBuf, SIZE_MAX);
		check("readU16 with SIZE_MAX offset throws", false);
	}
	catch (const std::out_of_range&) {
		check("readU16 with SIZE_MAX offset throws", true);
	}

	return 0;
}


int main()
{
	aes_example();
	
	rsa_example();

	endian_test();

	return 0;
}
