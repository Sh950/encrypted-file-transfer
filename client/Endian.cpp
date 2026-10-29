#include "Endian.h"
#include <stdexcept>

void appendU16(std::vector<uint8_t>& out, uint16_t value)
{
	out.push_back(static_cast<uint8_t>(value & 0xFF));
	out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
}

void appendU32(std::vector<uint8_t>& out, uint32_t value)
{
	out.push_back(static_cast<uint8_t>(value & 0xFF));
	out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
	out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
	out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}
	
uint16_t readU16(const std::vector<uint8_t>& in, size_t offset)
{
	// Check without addition: offset + n could overflow and wrap around to a small value.
	// First make sure offset is inside the buffer, so the subtraction cannot wrap.
	if (offset > in.size() || in.size() - offset < sizeof(uint16_t))
		throw std::out_of_range("readU16: offset out of range");
	return static_cast<uint16_t>(in[offset] | (in[offset + 1] << 8));
}

uint32_t readU32(const std::vector<uint8_t>& in, size_t offset)
{
	if (offset > in.size() || in.size() - offset < sizeof(uint32_t))
		throw std::out_of_range("readU32: offset out of range");
	// Cast each byte to uint32_t before shifting, so the << 24 is done on an unsigned type
	// and never touches the sign bit of an int.
	return static_cast<uint32_t>(in[offset])
		| (static_cast<uint32_t>(in[offset + 1]) << 8)
		| (static_cast<uint32_t>(in[offset + 2]) << 16)
		| (static_cast<uint32_t>(in[offset + 3]) << 24);
}