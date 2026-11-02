#include "Base64Wrapper.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Protocol.h"

#include <iostream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include "Endian.h"
#include <vector>
#include <string>

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

int protocol_test()
{
	std::cout << std::endl << std::endl << "----- PROTOCOL TEST -----" << std::endl << std::endl;

	// 1. Registration request: zero ID, code 825, 255-byte name payload
	Protocol::ClientId id{};	// {} zero-fills all 16 bytes
	std::vector<uint8_t> payload(Protocol::NAME_SIZE, 0);
	std::vector<uint8_t> req = Protocol::buildRequest(id, Protocol::RequestCode::Register, payload);

	check("request size == 278 (23 + 255)", req.size() == Protocol::REQUEST_HEADER_SIZE + Protocol::NAME_SIZE);

	// Bytes 0..15 - client ID, all zeros
	check("client ID == 16 zeros",
		std::vector<uint8_t>(req.begin(), req.begin() + 16) == std::vector<uint8_t>(16, 0));

	// Bytes 16..22 - version, code, payload size
	check("header bytes 16..22 == 03 39 03 FF 00 00 00",
		std::vector<uint8_t>(req.begin() + 16, req.begin() + 23) == std::vector<uint8_t>{ 0x03, 0x39, 0x03, 0xFF, 0x00, 0x00, 0x00 });
	hexify(req.data() + 16, 7);

	// 2. Non-zero ID - make sure the ID is copied as is, byte order unchanged
	Protocol::ClientId id2{};
	for (size_t i = 0; i < id2.size(); i++)
		id2[i] = static_cast<uint8_t>(i + 1);	// 01 02 03 ... 10
	std::vector<uint8_t> req2 = Protocol::buildRequest(id2, Protocol::RequestCode::SendFile, {});
	check("ID copied as 01..10", std::vector<uint8_t>(req2.begin(), req2.begin() + 16) == std::vector<uint8_t>(id2.begin(), id2.end()));

	// 3. Code 828 = 0x033C -> 3C 03
	check("code 828 == 3C 03", req2[17] == 0x3C && req2[18] == 0x03);

	// 4. Empty payload - header only, size field 00 00 00 00
	check("empty payload -> size 23", req2.size() == Protocol::REQUEST_HEADER_SIZE);
	check("empty payload -> size field == 00 00 00 00",readU32(req2, 19) == 0);

	return 0;
}


int name_field_test()
{
	std::cout << std::endl << std::endl << "----- NAME FIELD TEST -----" << std::endl << std::endl;

	// 1. Normal name: 255 bytes, name at the start, then zeros
	std::vector<uint8_t> f = Protocol::makeNameField("Shimon");
	check("size == 255", f.size() == Protocol::NAME_SIZE);
	check("starts with 53 68 69 6D 6F 6E 00",
		std::vector<uint8_t>(f.begin(), f.begin() + 7) == std::vector<uint8_t>{ 0x53, 0x68, 0x69, 0x6D, 0x6F, 0x6E, 0x00 });
	check("rest is zeros", std::all_of(f.begin() + 6, f.end(), [](uint8_t b) { return b == 0; }));
	hexify(f.data(), 16);

	// 2. Boundary: 254 chars - the longest legal name; last byte must be the terminator
	std::vector<uint8_t> f254 = Protocol::makeNameField(std::string(Protocol::NAME_SIZE - 1, 'a'));
	check("254 chars accepted, last byte == 00", f254.size() == Protocol::NAME_SIZE && f254.back() == 0x00);

	// 3. Boundary: 255 chars - no room for the terminator
	try {
		Protocol::makeNameField(std::string(Protocol::NAME_SIZE, 'a'));
		check("255 chars throws length_error", false);
	}
	catch (const std::length_error&) {
		check("255 chars throws length_error", true);
	}

	// 4. Empty name
	try {
		Protocol::makeNameField("");
		check("empty name throws invalid_argument", false);
	}
	catch (const std::invalid_argument&) {
		check("empty name throws invalid_argument", true);
	}

	// 5. Embedded \0 - the length 5 is required, otherwise the literal stops at \0
	try {
		Protocol::makeNameField(std::string("ab\0cd", 5));
		check("embedded \\0 throws invalid_argument", false);
	}
	catch (const std::invalid_argument&) {
		check("embedded \\0 throws invalid_argument", true);
	}

	// 6. Control character (newline)
	try {
		Protocol::makeNameField("ab\ncd");
		check("newline throws invalid_argument", false);
	}
	catch (const std::invalid_argument&) {
		check("newline throws invalid_argument", true);
	}

	// 7. Non-ASCII: Hebrew letter shin in UTF-8 (D7 A9), written as bytes to avoid source encoding issues
	try {
		Protocol::makeNameField("file_\xD7\xA9.txt");
		check("non-ASCII throws invalid_argument", false);
	}
	catch (const std::invalid_argument&) {
		check("non-ASCII throws invalid_argument", true);
	}

	return 0;
}

int public_key_payload_test()
{
	std::cout << std::endl << std::endl << "----- PUBLIC KEY PAYLOAD TEST -----" << std::endl << std::endl;

	// A real public key from the course wrapper - exactly 160 bytes
	RSAPrivateWrapper rsa;
	std::string pubkey = rsa.getPublicKey();
	std::vector<uint8_t> p = Protocol::makePublicKeyPayload("Shimon", pubkey);

	check("size == 415 (255 + 160)", p.size() == Protocol::NAME_SIZE + Protocol::PUBLIC_KEY_SIZE);
	check("name at offset 0", p[0] == 'S' && p[5] == 'n' && p[6] == 0x00);
	check("key at offset 255",
		std::equal(pubkey.begin(), pubkey.end(), p.begin() + Protocol::NAME_SIZE,
			[](char a, uint8_t b) { return static_cast<uint8_t>(a) == b; }));

	// Wrong key size must throw, not produce a malformed payload
	try {
		Protocol::makePublicKeyPayload("Shimon", std::string(100, 'x'));
		check("short key throws length_error", false);
	}
	catch (const std::length_error&) {
		check("short key throws length_error", true);
	}

	// Invalid name - the error comes from makeNameField, through this function
	try {
		Protocol::makePublicKeyPayload("", pubkey);
		check("empty name throws invalid_argument", false);
	}
	catch (const std::invalid_argument&) {
		check("empty name throws invalid_argument", true);
	}

	return 0;
}


int main()
{
	aes_example();
	
	rsa_example();

	endian_test();

	protocol_test();

	name_field_test();

	public_key_payload_test();

	return 0;
}
