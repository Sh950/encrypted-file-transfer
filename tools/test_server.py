"""Test server for developing the client. Grows milestone by milestone. NOT the assignment server."""
import socket
import struct
import uuid

HOST, PORT = "127.0.0.1", 1234
SERVER_VERSION = 3
REQUEST_HEADER = struct.Struct("<16sBHI")   # client id, version, code, payload size
RESPONSE_HEADER = struct.Struct("<BHI")     # version, code, payload size
NAME_SIZE = 255

clients = {}   # name -> client id (16 bytes), kept while the server runs


def recv_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("client disconnected")
        data += chunk
    return data


def send_response(conn, code, payload=b""):
    conn.sendall(RESPONSE_HEADER.pack(SERVER_VERSION, code, len(payload)) + payload)
    print(f"[server] sent {code}")


def parse_name(field):
    return field.split(b"\0", 1)[0].decode("ascii")


def handle_register(conn, client_id, payload):
    name = parse_name(payload[:NAME_SIZE])
    if name in clients:
        print(f"[server] name '{name}' is already registered")
        send_response(conn, 1601)
        return
    new_id = uuid.uuid4().bytes
    clients[name] = new_id
    print(f"[server] registered '{name}' as {new_id.hex()}")
    send_response(conn, 1600, new_id)


HANDLERS = {825: handle_register}


def serve(conn):
    while True:
        client_id, version, code, size = REQUEST_HEADER.unpack(recv_exact(conn, REQUEST_HEADER.size))
        payload = recv_exact(conn, size)
        print(f"[server] received {code} (client version {version}, {size} payload bytes)")
        handler = HANDLERS.get(code)
        if handler is None:
            send_response(conn, 1607)
        else:
            handler(conn, client_id, payload)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen()
        print(f"[server] test server listening on {HOST}:{PORT}")
        while True:
            conn, addr = server.accept()
            print(f"[server] connected: {addr}")
            with conn:
                try:
                    serve(conn)
                except ConnectionError:
                    print("[server] disconnected")


if __name__ == "__main__":
    main()