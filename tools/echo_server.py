# Test helper only - not part of the submission.
# Echoes back every byte it receives, so the client can test sendAll / recvExact.
import socket

HOST, PORT = "127.0.0.1", 1234

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"echo server listening on {HOST}:{PORT}")
    while True:
        conn, addr = server.accept()
        with conn:
            print("connected:", addr)
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                conn.sendall(data)
        print("disconnected")