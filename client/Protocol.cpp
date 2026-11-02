#include "Protocol.h"
#include "Endian.h"
#include <limits>
#include <stdexcept>
#include <vector>

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
}