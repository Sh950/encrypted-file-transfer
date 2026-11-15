#pragma once

#include <cstdint>
#include <vector>

namespace Cksum
{
	// CRC identical to the POSIX/Linux `cksum` command. Computed on the original (unencrypted) file.
	uint32_t computeCksum(const std::vector<uint8_t>& data);
}
