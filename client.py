import socket
import struct


def get_login_request(sequence, username, password):
    assert len(username) < 32
    assert len(password) < 32
    return struct.pack("!HBB32s32s", 4 + 32 + 32, 0, sequence, username.encode(), password.encode())


def get_echo_request(sequence, cipher_msg):
    return struct.pack("!HBB", 4 + len(cipher_msg), 2, sequence) + cipher_msg


def main():
    HOST = "localhost"
    PORT = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for request in [
            get_login_request(1, "user", "pass"),
            get_echo_request(2, b"ciphermessage"),
        ]:
            s.sendall(request)
            data = s.recv(1024)
            print(f"Received {data!r}")


if __name__ == "__main__":
    main()
