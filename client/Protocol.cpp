#include "Protocol.h"
#include "Endian.h"
#include <limits>
#include <stdexcept>
#include <vector>
#include <algorithm>

namespace Protocol
{
	std::vector<uint8_t> buildRequest(const ClientId& clientId, RequestCode code, const std::vector<uint8_t>& payload) {

		std::vector<uint8_t> request;
		request.reserve(REQUEST_HEADER_SIZE + payload.size());
		request.insert(request.end(), clientId.begin(), clientId.end());
		request.push_back(CLIENT_VERSION);
		appendU16(request, static_cast<uint16_t>(code));
		if (payload.size() > std::numeric_limits<uint32_t>::max())
			throw std::length_error("buildRequest: payload too large for a 4-byte size field");
		appendU32(request, static_cast<uint32_t>(payload.size()));
		request.insert(request.end(), payload.begin(), payload.end());

		return request;
	}

	std::vector<uint8_t> makeNameField(const std::string& name) {
		if (name.empty())
			throw std::invalid_argument("makeNameField: name is empty");
		if (name.size() >= NAME_SIZE)
			throw std::length_error("makeNameField: name too long for the name field");
		for (char c : name)
		{
			unsigned char uc = static_cast<unsigned char>(c);
			if (uc < PRINTABLE_ASCII_MIN || uc > PRINTABLE_ASCII_MAX)
				throw std::invalid_argument("makeNameField: name contains a non-printable or non-ASCII character");
		}
		std::vector<uint8_t> nameField(NAME_SIZE, 0);
		std::copy(name.begin(), name.end(), nameField.begin());
		return nameField;
	}

	std::vector<uint8_t> makePublicKeyPayload(const std::string& name, const std::string& publicKey) {

		if (publicKey.size() != PUBLIC_KEY_SIZE)
			throw std::length_error("makePublicKeyPayload: public key must be " + std::to_string(PUBLIC_KEY_SIZE) + " bytes");

		std::vector<uint8_t> payload = makeNameField(name);

		payload.insert(payload.end(), publicKey.begin(), publicKey.end());

		return payload;
	}

	std::vector<uint8_t> makeFilePacketPayload(uint32_t contentSize,
		uint32_t origSize,
		uint16_t packetNumber,
		uint16_t totalPackets,
		const std::string& fileName,
		const std::vector<uint8_t>& chunk)
	{
		if (totalPackets == 0)
			throw std::invalid_argument("makeFilePacketPayload: total packets must be at least 1");
		if (packetNumber == 0 || packetNumber > totalPackets)
			throw std::out_of_range("makeFilePacketPayload: packet number must be in 1..total packets");
		if (chunk.empty())
			throw std::invalid_argument("makeFilePacketPayload: packet content is empty");
		if (chunk.size() > contentSize)
			throw std::length_error("makeFilePacketPayload: packet larger than the whole encrypted file");

		std::vector<uint8_t> payload;
		payload.reserve(FILE_PACKET_HEADER_SIZE + chunk.size());

		appendU32(payload, contentSize);	
		appendU32(payload, origSize);

		appendU16(payload, packetNumber);
		appendU16(payload, totalPackets);

		std::vector<uint8_t> nameField = makeNameField(fileName);
		payload.insert(payload.end(), nameField.begin(), nameField.end());

		payload.insert(payload.end(), chunk.begin(), chunk.end());

		return payload;
	}

	size_t expectedPayloadSize(ResponseCode code)
	{
		switch (code)
		{
		case ResponseCode::RegisterOk:
		case ResponseCode::Ack:
		case ResponseCode::ReconnectDenied:
			return CLIENT_ID_RESPONSE_SIZE;

		case ResponseCode::AesKey:
		case ResponseCode::ReconnectOk:
			return AES_KEY_RESPONSE_SIZE;

		case ResponseCode::FileReceived:
			return FILE_RECEIVED_RESPONSE_SIZE;

		case ResponseCode::RegisterFailed:
		case ResponseCode::GeneralError:
			return EMPTY_RESPONSE_SIZE;

		default:
			throw std::invalid_argument("expectedPayloadSize: unknown response code");
		}
	}

	// Validates the header before the payload is read: all fields come from the network.
	ResponseHeader parseResponseHeader(const std::vector<uint8_t>& header)
	{
		if (header.size() != RESPONSE_HEADER_SIZE)
			throw std::length_error("parseResponseHeader: header must be " + std::to_string(RESPONSE_HEADER_SIZE) + " bytes");

		ResponseHeader result{};

		// The assignment fixes the server version at 3, any other version violates the protocol.
		result.version = header[0];
		if (result.version != SERVER_VERSION)
			throw std::invalid_argument("parseResponseHeader: unsupported server version " + std::to_string(result.version));

		// Cast to the enum only after checking the code is known.
		const uint16_t rawCode = readU16(header, VERSION_SIZE);
		const uint16_t firstCode = static_cast<uint16_t>(ResponseCode::RegisterOk);
		const uint16_t lastCode = static_cast<uint16_t>(ResponseCode::GeneralError);
		if (rawCode < firstCode || rawCode > lastCode)
			throw std::invalid_argument("parseResponseHeader: unknown response code " + std::to_string(rawCode));
		result.code = static_cast<ResponseCode>(rawCode);

		// Exact size per code, checked before any allocation (prevents a huge size from exhausting memory).
		result.payloadSize = readU32(header, VERSION_SIZE + CODE_SIZE);
		if (result.payloadSize != expectedPayloadSize(result.code))
			throw std::length_error("parseResponseHeader: payload size " + std::to_string(result.payloadSize)
				+ " does not match code " + std::to_string(rawCode));

		return result;
	}
}