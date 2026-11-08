"""Test server for developing the client. Grows milestone by milestone. NOT the assignment server."""
import socket
import struct
import uuid
import os
from Crypto.Util.Padding import unpad
from cksum import memcrc
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

HOST, PORT = "127.0.0.1", 1234
SERVER_VERSION = 3
REQUEST_HEADER = struct.Struct("<16sBHI")   # client id, version, code, payload size
RESPONSE_HEADER = struct.Struct("<BHI")     # version, code, payload size
NAME_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32
FILE_PACKET_HEADER = struct.Struct("<IIHH")   # content size, orig size, packet number, total packets
RECEIVED_DIR = os.path.join(os.path.dirname(__file__), "received")
transfers = {}   # (client id, file name) -> list of encrypted chunks

clients = {}   # name -> {"id", "public_key", "aes_key"}, kept only while the server runs

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

def find_client(client_id):
    for name, entry in clients.items():
        if entry["id"] == client_id:
            return name, entry
    return None, None

def name_field(name):
    return name.encode("ascii").ljust(NAME_SIZE, b"\0")

def handle_file_packet(conn, client_id, payload):
    content_size, orig_size, packet, total = FILE_PACKET_HEADER.unpack(payload[:FILE_PACKET_HEADER.size])
    offset = FILE_PACKET_HEADER.size
    file_name = parse_name(payload[offset:offset + NAME_SIZE])
    chunk = payload[offset + NAME_SIZE:]
    name, entry = find_client(client_id)
    if entry is None or entry["aes_key"] is None:
        send_response(conn, 1607)
        return

    key = (client_id, file_name)
    if packet == 1:
        transfers[key] = []
    transfers[key].append(chunk)
    if packet < total:
        return   # no answer until the last packet

    encrypted = b"".join(transfers.pop(key))
    content = unpad(AES.new(entry["aes_key"], AES.MODE_CBC, iv=bytes(16)).decrypt(encrypted), 16)
    crc = memcrc(content)
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    with open(os.path.join(RECEIVED_DIR, file_name), "wb") as f:
        f.write(content)
    print(f"[server] '{name}': received {file_name}: {total} packet(s), {len(content)} bytes, CRC {crc}")
    send_response(conn, 1603, client_id + struct.pack("<I", len(encrypted)) + name_field(file_name) + struct.pack("<I", crc))


def handle_crc_ok(conn, client_id, payload):
    print(f"[server] CRC OK for {parse_name(payload[:NAME_SIZE])}")
    send_response(conn, 1604, client_id)


def handle_crc_retry(conn, client_id, payload):
    print(f"[server] CRC mismatch for {parse_name(payload[:NAME_SIZE])} - client will resend")


def handle_crc_abort(conn, client_id, payload):
    print(f"[server] CRC failed 4 times for {parse_name(payload[:NAME_SIZE])} - client gave up")
    send_response(conn, 1604, client_id)

HANDLERS = {825: handle_register, 826: handle_public_key, 827: handle_reconnect,
            828: handle_file_packet, 900: handle_crc_ok, 901: handle_crc_retry, 902: handle_crc_abort}

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