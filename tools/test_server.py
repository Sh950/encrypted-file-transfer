"""Test server for developing the client. Grows milestone by milestone. NOT the assignment server."""
import socket
import struct
import uuid
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

HOST, PORT = "127.0.0.1", 1234
SERVER_VERSION = 3
REQUEST_HEADER = struct.Struct("<16sBHI")   # client id, version, code, payload size
RESPONSE_HEADER = struct.Struct("<BHI")     # version, code, payload size
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32

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

def handle_public_key(conn, client_id, payload):
    name = parse_name(payload[:NAME_SIZE])
    public_key = payload[NAME_SIZE:NAME_SIZE + PUBLIC_KEY_SIZE]
    entry = clients.get(name)
    if entry is None or entry["id"] != client_id:
        print(f"[server] unknown client '{name}' or client ID mismatch")
        send_response(conn, 1607)
        return
    aes_key = get_random_bytes(AES_KEY_SIZE)
    encrypted = PKCS1_OAEP.new(RSA.import_key(public_key)).encrypt(aes_key)
    entry["aes_key"] = aes_key
    entry["public_key"] = public_key
    print(f"[server] '{name}': AES key created, encrypted with the client's public key ({len(encrypted)} bytes)")
    send_response(conn, 1602, client_id + encrypted)

def handle_register(conn, client_id, payload):
    name = parse_name(payload[:NAME_SIZE])
    if name in clients:
        print(f"[server] name '{name}' is already registered")
        send_response(conn, 1601)
        return
    new_id = uuid.uuid4().bytes
    clients[name] = {"id": new_id, "public_key": None, "aes_key": None}
    print(f"[server] registered '{name}' as {new_id.hex()}")
    send_response(conn, 1600, new_id)

def handle_reconnect(conn, client_id, payload):
    name = parse_name(payload[:NAME_SIZE])
    entry = clients.get(name)
    if entry is None or entry["id"] != client_id or entry["public_key"] is None:
        print(f"[server] reconnect denied for '{name}'")
        send_response(conn, 1606, client_id)
        return
    aes_key = get_random_bytes(AES_KEY_SIZE)
    encrypted = PKCS1_OAEP.new(RSA.import_key(entry["public_key"])).encrypt(aes_key)
    entry["aes_key"] = aes_key
    print(f"[server] '{name}' reconnected: new AES key, encrypted with the stored public key")
    send_response(conn, 1605, client_id + encrypted)

HANDLERS = {825: handle_register, 826: handle_public_key, 827: handle_reconnect}

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