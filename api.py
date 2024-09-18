from flask import Flask, request, jsonify
import socket
from packet import Packet

app = Flask(__name__)

# Default configuration
DEFAULT_URL = "network.lucoin.pro"
DEFAULT_PORT = 3001
DEFAULT_SOCKET_TIMEOUT = 3000

@app.route('/api/blockchain', methods=['GET'])
def get_blockchain():
    limit = request.args.get('limit', 25, type=int)
    packet = Packet(Packet.GETCHAIN, {"limit": limit})
    response = send_packet(packet)
    return jsonify({'data': response})

@app.route('/api/create', methods=['GET'])
def create_wallet():
    packet = Packet(Packet.ADDWALLET, {})
    response = send_packet(packet)
    return jsonify({'data': response})

@app.route('/api/balance', methods=['GET'])
def get_balance():
    wallet = request.args.get('wallet', '')
    packet = Packet(Packet.BALANCE, {"address": wallet})
    response = send_packet(packet)
    return jsonify({'data': response})

@app.route('/api/send', methods=['POST'])
def send_transaction():
    data = request.json
    amount = data.get('amount')
    recipient = data.get('recipient')
    fee = float(amount) * data.get('fee', 0.01)  # default fee value
    packet = Packet(Packet.TRANSACT, {
        "recipient": recipient,
        "amount": float(amount),
        "fee": fee,
        "sender": data.get('sender', ''),
        "key": data.get('key', '')
    })
    response = send_packet(packet)
    return jsonify({'data': response})

@app.route('/api/mempool', methods=['GET'])
def get_mempool():
    limit = request.args.get('limit', 25, type=int)
    packet = Packet(Packet.GETMEM, {
        "limit": limit,
        "highfee": False
    })
    response = send_packet(packet)
    return jsonify({'data': response})

def send_packet(packet):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            client.connect((DEFAULT_URL, DEFAULT_PORT))
            client.settimeout(DEFAULT_SOCKET_TIMEOUT / 1000)
            client.sendall(packet.encode())
            data = client.recv(1024 * 8)
            if data:
                return data.decode()
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    app.run(debug=True)