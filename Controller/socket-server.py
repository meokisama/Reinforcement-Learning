import socket

HOST = "192.168.106.130"  # Standard loopback interface address (localhost)
PORT = 51234  # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print("Connected by ", addr)
        while True:
            data = conn.recv(65900)
            if not data:
                break
            print(data.decode('latin1')[:4])