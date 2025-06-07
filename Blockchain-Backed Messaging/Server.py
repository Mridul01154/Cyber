import socket
import threading
import hashlib
import datetime
import json
import ssl
import time

connected_clients = []
clients_lock = threading.Lock()

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current['previous_hash'] != previous['hash']:
                print(f"[!] Invalid chain at block {i}: hash mismatch.")
                return False

            recalculated_hash = self.calculate_hash(current)
            if current['hash'] != recalculated_hash:
                print(f"[!] Invalid chain at block {i}: hash recalculation mismatch.")
                return False

        print("[✔] Blockchain validated successfully.")
        return True

    def create_genesis_block(self):
        genesis = self.create_block("System", "Genesis Block", "0")
        self.chain.append(genesis)

    def create_block(self, sender, message, prev_hash):
        index = len(self.chain)
        timestamp = str(datetime.datetime.now())
        block_data = {
            'index': index,
            'timestamp': timestamp,
            'sender': sender,
            'message': message,
            'previous_hash': prev_hash
        }
        block_data['hash'] = self.calculate_hash(block_data)
        return block_data

    def calculate_hash(self, data):
        block_str = f"{data['index']}{data['timestamp']}{data['sender']}{data['message']}{data['previous_hash']}"
        return hashlib.sha256(block_str.encode()).hexdigest()

    def add_block(self, sender, message):
        last_hash = self.chain[-1]['hash']
        new_block = self.create_block(sender, message, last_hash)
        self.chain.append(new_block)

    def get_chain(self):
        return self.chain

blockchain = Blockchain()
last_chain_hash = None

def get_chain_hash(chain):
    return hashlib.sha256(json.dumps(chain, sort_keys=True).encode()).hexdigest()

def broadcast_chain_periodically():
    global last_chain_hash
    while True:
        time.sleep(15)
        current_chain = blockchain.get_chain()
        current_hash = get_chain_hash(current_chain)

        last_chain_hash = current_hash
        chain_data = json.dumps(current_chain)
        with clients_lock:
            for conn in connected_clients[:]:
                try:
                    conn.send(chain_data.encode())
                except Exception as e:
                    print("[!] Failed to send to client, removing:", e)
                    connected_clients.remove(conn)

def handle_client(conn, addr):
    try:
        print(f"[+] Connected by {addr}")
        with clients_lock:
            connected_clients.append(conn)

        while True:
            data = conn.recv(1024)
            if not data:
                break

            msg = json.loads(data.decode())

            if msg.get("type") == "refresh":
                print(f"[↻] Refresh request from {addr}")
            else:
                print(f"[+] Received message from {msg['sender']}: {msg['message']}")

               
                if blockchain.validate_chain():
                    blockchain.add_block(msg['sender'], msg['message'])
                    global last_chain_hash
                    last_chain_hash = None
                else:
                    error_msg = json.dumps({"error": "Chain validation failed"})
                    conn.send(error_msg.encode())
                    continue  

            response = json.dumps(blockchain.get_chain())
            conn.send(response.encode())

    except Exception as e:
        print("[!] Error handling client:", e)

    finally:
        with clients_lock:
            if conn in connected_clients:
                connected_clients.remove(conn)
        conn.close()
        print(f"[-] Connection with {addr} closed")


HOST = '0.0.0.0'
PORT = 9999

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"[+] TLS Server started on port {PORT}")
threading.Thread(target=broadcast_chain_periodically, daemon=True).start()


while True:
        try:
            client_socket, addr = server.accept()
            secure_conn = context.wrap_socket(client_socket, server_side=True)
            threading.Thread(target=handle_client, args=(secure_conn, addr)).start()
        except ssl.SSLError as ssl_error:
            print(f"[!] SSL error from {addr}: {ssl_error}")
            client_socket.close()
        except Exception as e:
            print("[!] General server error:", e)

