#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>

#include "TcpConnection.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <stdexcept>

static_assert(sizeof(SOCKET) == sizeof(std::uintptr_t), "SOCKET must fit in std::uintptr_t");

namespace
{
	constexpr WORD WINSOCK_VERSION_REQUIRED = MAKEWORD(2, 2);

	// send/recv take the length as int, so larger buffers are moved in chunks
	constexpr size_t MAX_CHUNK = static_cast<size_t>(std::numeric_limits<int>::max());

	SOCKET toSocket(std::uintptr_t value)
	{
		return static_cast<SOCKET>(value);
	}

	[[noreturn]] void throwSocketError(const std::string& what)
	{
		throw std::runtime_error(what + " (Winsock error " + std::to_string(WSAGetLastError()) + ")");
	}
}


WinsockSession::WinsockSession()
{
	WSADATA data{};
	const int result = WSAStartup(WINSOCK_VERSION_REQUIRED, &data);
	if (result != 0)
		throw std::runtime_error("WSAStartup failed (error " + std::to_string(result) + ")");
}

WinsockSession::~WinsockSession()
{
	WSACleanup();
}

TcpConnection::TcpConnection(const std::string& host, uint16_t port, std::chrono::milliseconds timeout)

	: socket_(static_cast<std::uintptr_t>(INVALID_SOCKET))
{
	if (timeout.count() <= 0 || timeout.count() > static_cast<long long>(MAXDWORD))
		throw std::invalid_argument("TcpConnection: invalid timeout");

	const DWORD timeoutMs = static_cast<DWORD>(timeout.count());
	// Resolve host and port into one or more addresses (IPv4 / IPv6 / a host name)
	addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	const std::string portText = std::to_string(port);
	addrinfo* addresses = nullptr;
	const int resolveResult = getaddrinfo(host.c_str(), portText.c_str(), &hints, &addresses);
	if (resolveResult != 0)
		throw std::runtime_error("cannot resolve server address \"" + host + "\" (error " + std::to_string(resolveResult) + ")");
	// getaddrinfo allocates the list; the unique_ptr frees it on every exit path, including exceptions
	std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addressList(addresses, &freeaddrinfo);
	int lastError = 0;
	for (addrinfo* address = addresses; address != nullptr; address = address->ai_next)
	{
		SOCKET s = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
		if (s == INVALID_SOCKET)
		{
			lastError = WSAGetLastError();
			continue;
		}

		// Timeouts are set before connect, so a failure here is handled like any other failed attempt
		const bool timeoutsSet =
			setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs)) == 0 &&
			setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs)) == 0;

		if (timeoutsSet && connect(s, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0)
		{
			socket_ = static_cast<std::uintptr_t>(s);
			return;
		}

		lastError = WSAGetLastError();
		closesocket(s);
	}

	throw std::runtime_error("cannot connect to " + host + ":" + portText
		+ " (Winsock error " + std::to_string(lastError) + ")");
}

TcpConnection::~TcpConnection()
{
	if (toSocket(socket_) != INVALID_SOCKET)
		closesocket(toSocket(socket_));
}

void TcpConnection::sendAll(const std::vector<uint8_t>& data)
{
	size_t sent = 0;
	while (sent < data.size())
	{
		const int chunk = static_cast<int>(std::min(data.size() - sent, MAX_CHUNK));
		const int result = send(toSocket(socket_), reinterpret_cast<const char*>(data.data() + sent), chunk, 0);
		if (result == SOCKET_ERROR || result == 0)
			throwSocketError("send failed");
		sent += static_cast<size_t>(result);
	}
}

std::vector<uint8_t> TcpConnection::recvExact(size_t size)
{
	std::vector<uint8_t> buffer(size);
	size_t received = 0;
	while (received < size)
	{
		const int chunk = static_cast<int>(std::min(size - received, MAX_CHUNK));
		const int result = recv(toSocket(socket_), reinterpret_cast<char*>(buffer.data() + received), chunk, 0);
		if (result == 0)
			throw std::runtime_error("the server closed the connection");
		if (result == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAETIMEDOUT)
				throw std::runtime_error("timed out waiting for the server");
			throwSocketError("recv failed");
		}
		received += static_cast<size_t>(result);
	}
	return buffer;
}