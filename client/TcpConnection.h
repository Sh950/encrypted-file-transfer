#pragma once
#include<vector>
#include<string>
#include<cstdint>
#include<chrono>
#include <cstddef>

class WinsockSession
{
public:
	WinsockSession();
	~WinsockSession();

	WinsockSession(const WinsockSession&) = delete;
	WinsockSession& operator=(const WinsockSession&) = delete;
};

class TcpConnection
{
public:
	TcpConnection(const std::string& host, uint16_t port, std::chrono::milliseconds timeout);
	~TcpConnection();

	TcpConnection(const TcpConnection&) = delete;
	TcpConnection& operator=(const TcpConnection&) = delete;

	void sendAll(const std::vector<uint8_t>& data);
	std::vector<uint8_t> recvExact(size_t size);

private:
	std::uintptr_t socket_;	// a Winsock SOCKET, stored as its underlying type to keep winsock2.h out of this header
};