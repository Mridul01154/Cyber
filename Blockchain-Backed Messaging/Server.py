import socket
import threading
import hashlib
import datetime
import json

class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

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

def handle_client(conn, addr):
    try:
        print(f"[+] Connected by {addr}")  

        data = conn.recv(1024).decode()
        msg = json.loads(data)
        print(f"[+] Received message from {msg['sender']}: {msg['message']}")  

        blockchain.add_block(msg['sender'], msg['message'])

        response = json.dumps(blockchain.get_chain())
        conn.send(response.encode())

    except Exception as e:
        print("Error:", e)
    finally:
        conn.close()
        print(f"[-] Connection with {addr} closed")  


HOST = '0.0.0.0'
PORT = 9999
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[+] Server started on port {PORT}")
while True:
    conn, addr = server.accept()
    threading.Thread(target=handle_client, args=(conn, addr)).start()
