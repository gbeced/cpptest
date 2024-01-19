import socket
import struct


def get_login_request(sequence, username, password):
    assert len(username) < 32
    assert len(password) < 32
    return struct.pack("!HBB32s32s", 4 + 32 + 32, 0, sequence, username.encode(), password.encode())


def get_echo_request(sequence, cipher_msg):
    return struct.pack("!HBBH", 4 + 2 + len(cipher_msg), 2, sequence, len(cipher_msg)) + cipher_msg


def calculate_checksum(msg):
    ret = 0
    for c in msg:
        ret += ord(c)
    return ret % 256


def next_key(key):
    return (key * 1103515245 + 12345) % 0x7FFFFFFF


def encrypt_message(sequence, username, password, message):
    initial_key = (sequence << 16 | calculate_checksum(username) << 8 | calculate_checksum(password)) % 0xFFFFFFFF
    key = next_key(initial_key)

    ret = b""
    for c in message:
        ret += (ord(c) ^ (key % 256)).to_bytes(1, "big")
        key = next_key(key)
    return ret


def main():
    HOST = "localhost"
    PORT = 12345
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        for request in [
            get_login_request(1, "testuser", "testpass"),
            get_echo_request(87, encrypt_message(87, "testuser", "testpass", "0")),
        ]:
            s.sendall(request)
            data = s.recv(1024)
            print(f"Received {data!r}")


if __name__ == "__main__":
    main()
