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
}