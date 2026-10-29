#pragma once
#include <cstdint>
#include <vector>

void appendU16(std::vector<uint8_t>& out, uint16_t value);
void appendU32(std::vector<uint8_t>& out, uint32_t value);

uint16_t readU16(const std::vector<uint8_t>& in, size_t offset);
uint32_t readU32(const std::vector<uint8_t>& in, size_t offset);