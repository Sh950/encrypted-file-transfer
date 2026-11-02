#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <vector>

#include "AESWrapper.h"
#include "RSAWrapper.h"

namespace Protocol
{
	// ----- Version -----
	constexpr uint8_t CLIENT_VERSION = 3;

	// ----- Request codes (client -> server) -----
	enum class RequestCode : uint16_t
	{
		Register = 825,
		SendPublicKey = 826,
		Reconnect = 827,
		SendFile = 828,
		CrcOk = 900,
		CrcRetry = 901,
		CrcAbort = 902
	};

	// ----- Response codes (server -> client) -----
	enum class ResponseCode : uint16_t
	{
		RegisterOk = 1600,
		RegisterFailed = 1601,
		AesKey = 1602,
		FileReceived = 1603,
		Ack = 1604,
		ReconnectOk = 1605,
		ReconnectDenied = 1606,
		GeneralError = 1607
	};

	// ----- Header field sizes -----
	constexpr size_t CLIENT_ID_SIZE = 16;
	using ClientId = std::array<uint8_t, CLIENT_ID_SIZE>;
	constexpr size_t VERSION_SIZE = 1;
	constexpr size_t CODE_SIZE = 2;
	constexpr size_t PAYLOAD_SIZE_SIZE = 4;

	constexpr size_t REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;
	constexpr size_t RESPONSE_HEADER_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;

	// ----- Payload field sizes -----
	constexpr size_t NAME_SIZE = 255;	// client name and file name, null terminated
	constexpr size_t CONTENT_SIZE_SIZE = 4;
	constexpr size_t ORIG_SIZE_SIZE = 4;
	constexpr size_t PACKET_NUMBER_SIZE = 2;
	constexpr size_t TOTAL_PACKETS_SIZE = 2;
	constexpr size_t CKSUM_SIZE = 4;

	// ----- Crypto sizes - taken from the wrappers, not redefined (single source of truth) -----
	constexpr size_t AES_KEY_SIZE = AESWrapper::DEFAULT_KEYLENGTH;
	constexpr size_t PUBLIC_KEY_SIZE = RSAPublicWrapper::KEYSIZE;
	constexpr size_t ENCRYPTED_AES_KEY_SIZE = RSAPrivateWrapper::BITS / 8;	// RSA output length = key length

	// ----- Limits from the assignment text -----
	constexpr int    MAX_FILE_SEND_ATTEMPTS = 4;	// first send + 3 resends, then 902
	constexpr int    MAX_SERVER_ERROR_RETRIES = 3;
	constexpr size_t MAX_CLIENT_NAME_LENGTH = 100;	// transfer.json

	// Compile-time checks: if anyone edits a size, the build fails instead of the protocol breaking silently.
	static_assert(REQUEST_HEADER_SIZE == 23, "request header must be 23 bytes");
	static_assert(RESPONSE_HEADER_SIZE == 7, "response header must be 7 bytes");
	static_assert(MAX_CLIENT_NAME_LENGTH < NAME_SIZE, "name must fit with its null terminator");

	std::vector<uint8_t> buildRequest(const ClientId& clientId, RequestCode code, const std::vector<uint8_t>& payload);
}
