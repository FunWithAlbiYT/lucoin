import sys
import time, random, hashlib
import socket, json, sqlite3
from threading import Thread
from packet import Packet, PTracker

HOST = '0.0.0.0'
PORT = 3001

chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

reward = 50
halving = 120_000

def calculate_block(pof, prev_hash, txs):
    return (
        str(pof)
        + str(prev_hash)
        + json.dumps(txs)
    )

def get_reward(height):
    halvings = height // halving
    return reward / (2 ** halvings)

def verify_block(pof, prev_hash, txs):
    difficulty = int(open("difficulty").read()) or 6
    data = calculate_block(pof, prev_hash, txs).encode()

    return hashlib.sha256(data).hexdigest().startswith('0' * difficulty)

def get_miner(txs):
    for tx in txs:
        if tx['sender'] == "Block Reward":
            return tx['recipient']

    return None

def gen_key():
    res = ""
    for _ in range(64):
        res += random.choice(chars)
    return res

def gen_txid():
    res = ""
    for _ in range(25):
        res += random.choice(chars)
    return res

def gen_wallet():
    res = ""
    for _ in range(42):
        res += random.choice(chars)
    return res

def sign(private, data):
    before = f"{data}:{private}"
    sh = hashlib.sha256(before.encode()).hexdigest()
    return sh

def verify(public, private, data):
    return sign(private, data) == public

def create_connection():
    conn = sqlite3.connect('database.sqlite')
    cur = conn.cursor()
    return conn, cur

def run(sql, params=()):
    conn, cur = create_connection()
    cur.execute(sql, params)
    conn.commit()
    conn.close()

def queryall(sql, cur, params=()):
    cur.execute(sql, params)
    columns = [desc[0] for desc in cur.description]
    return [dict(zip(columns, row)) for row in cur.fetchall()]

def query(sql, cur, params=()):
    cur.execute(sql, params)
    row = cur.fetchone()
    return dict(zip([desc[0] for desc in cur.description], row)) if row else None

def chain_size():
    conn, cur = create_connection()
    cur.execute("SELECT COUNT(*) FROM blocks;")
    size = cur.fetchone()[0]

    conn.close()
    return size

def compute_fees(txs):
    fees = 0
    for tx in txs:
        fees += tx['fee']
    return fees

def verify_txs(height, txs):
    conn, cur = create_connection()
    rewarded = False

    # tuple hell
    for tx in txs:
        wallet = query("SELECT * FROM wallets WHERE address = ?;", cur, (tx['sender'],))
        if ((not wallet or not verify(tx['key'], wallet['key'], tx['timestamp']))
        and (not rewarded and tx['sender'] != "Block Reward")):
            conn.close()
            return False
        
        if tx['sender'] == "Block Reward":
            rewarded = True
            if tx['amount'] > get_reward(height) + compute_fees(txs):
                conn.close()
                return False
            
    conn.close()
    if not rewarded:
        return False
    else:
        return True

def get_balance(address):
    conn, cur = create_connection()
    exists = query("SELECT * FROM wallets WHERE address = ?;", cur, (address,))

    balance = None
    if exists:
        balance = 0
        q = queryall(f"SELECT * FROM transactions WHERE recipient = ? OR sender = ?;", cur, (address,) *2)

        for transaction in q:
            sender = transaction['sender']
            public_key = transaction["key"]

            valid = True
            if transaction['sender'] != "Block Reward":
                private_key = query(f"SELECT * FROM wallets WHERE address = ?;", cur, (sender,))['key']
                valid = verify(public_key, private_key, transaction["timestamp"])

            if valid or transaction['sender'] == "Block Reward":
                amount = transaction["amount"]

                if transaction["recipient"] == address and transaction["confirmed"] == 1:
                    balance += amount - transaction['fee']
                elif transaction['sender'] == address:
                    balance -= amount

    cur.close()
    conn.close()
    return balance

run("""CREATE TABLE IF NOT EXISTS blocks (
        height INTEGER PRIMARY KEY,
        timestamp INTEGER,
        transactions TEXT,
        prevhash TEXT,
        hash TEXT,
        pof INTEGER,
        miner TEXT,
        size INTEGER
    );""")
run("""CREATE TABLE IF NOT EXISTS wallets (
        key TEXT,
        address TEXT
    );""")
run("""CREATE TABLE IF NOT EXISTS transactions (
        txid TEXT,
        timestamp INTEGER,
        amount INTEGER,
        fee INTEGER,
        key TEXT,
        recipient TEXT,
        sender TEXT,
        confirmed INTEGER DEFAULT 0
    );""")

def create_genesis():
    genesis_hash = hashlib.sha256(calculate_block(0, "0" * 64, []).encode()).hexdigest()
    run(f"""INSERT INTO blocks (timestamp, transactions, prevhash, hash, pof, miner, size) values (
    {round(time.time())}, "[]", "{"0" * 64}", "{genesis_hash}", 0, "Block Reward", 265
    );""")

#create_genesis()

trackers = []
def broadcast(packet):
    global trackers
    for sock in trackers:
        sock.sendall(packet)

def handle(client):
    global trackers
    conn, cur = create_connection()
    try:
        while True:
            raw = client.recv(1024).decode()
            if not raw:
                continue

            data = json.loads(raw)
            pack = Packet(data["type"], data["data"])
            
            if pack.type == Packet.GETCHAIN:
                limit = int(pack.data["limit"]) or 25
                chain = queryall("SELECT * FROM blocks ORDER BY height DESC LIMIT {};".format(limit), cur)

                client.sendall(Packet(Packet.RESPONSE, chain).encode())
            elif pack.type == Packet.TRACKER:
                trackers.append(client)
            elif pack.type == Packet.ADDWALLET:
                key, wallet = gen_key(), gen_wallet()
                run("INSERT INTO wallets (key, address) values ('{}', '{}')".format(key, wallet))
                
                client.sendall(Packet(Packet.RESPONSE, {
                    "key": key,
                    "wallet": wallet
                }).encode())
            elif pack.type == Packet.BALANCE:
                wallet = pack.data["address"]
                balance = get_balance(wallet)

                exists = True
                if balance is None:
                    exists = False
                    balance = 0
                
                client.sendall(Packet(Packet.RESPONSE, {
                    "balance": balance,
                    "exists": exists
                }).encode())
            elif pack.type == Packet.TRANSACT:
                sender = pack.data["sender"]
                recipient = pack.data["recipient"]
                amount = pack.data["amount"]
                fee = pack.data["fee"]

                rec = query("SELECT * FROM wallets WHERE address=?;", cur, (recipient,))
                sen = query("SELECT * FROM wallets WHERE address=?;", cur, (sender,))

                if rec and sen:
                    if sen["key"] == pack.data["key"]:
                        timestamp = round(time.time())
                        key = sign(sen["key"], timestamp)

                        if get_balance(sen["address"]) >= amount + fee:
                            if fee < amount and fee > 0:
                                txid = gen_txid()
                                run(f"""INSERT INTO transactions (txid, timestamp, key, recipient, sender, amount, fee)
                                    values (?,?,?,?,?,?,?);
                                    """, (txid, timestamp, key, recipient, sender, amount, fee))
                                
                                packdat = {
                                    "txid": txid,
                                    "timestamp": timestamp,
                                    "key": key,
                                    "recipient": recipient,
                                    "sender": sender,
                                    "amount": amount,
                                    "fee": fee
                                }

                                broadcast(Packet(PTracker.TRANSACTION, packdat).encode())
                                client.sendall(Packet(Packet.RESPONSE, packdat).encode())
                            else:
                                client.sendall(Packet(Packet.RESPONSE, {
                                    "code": 3,
                                    "message": "Fee higher than amount"
                                }).encode())
                        else:
                            client.sendall(Packet(Packet.RESPONSE, {
                                "code": 2,
                                "message": "Not enough balance"
                            }).encode())
                    else:
                        client.sendall(Packet(Packet.RESPONSE, {
                                "code": 1,
                                "message": "Invalid key"
                            }).encode())
                else:
                    client.sendall(Packet(Packet.RESPONSE, {
                        "code": 0,
                        "message": "Invalid Recipient/Sender"
                    }).encode())
            elif pack.type == Packet.GETMEM:
                limit = pack.data["limit"] if pack.data.get("limit") else 20
                order = "ORDER BY fee DESC" if pack.data["highfee"] else ''

                mempool = []
                for tx in queryall(("SELECT * FROM transactions WHERE "
                                   f"confirmed = 0 {order} LIMIT {limit}"), cur):
                    tx2 = tx.copy()
                    del tx2['confirmed']
                    mempool.append(tx2)

                client.sendall(Packet(Packet.RESPONSE, mempool).encode())
            elif pack.type == Packet.GETSIZE:
                client.sendall(Packet(Packet.RESPONSE, {
                    "size": chain_size()
                }).encode())
            elif pack.type == Packet.GETREQ:
                client.sendall(Packet(Packet.RESPONSE, {
                    "difficulty": open("difficulty").read()
                }).encode())
            elif pack.type == Packet.BROADCAST:
                txs = pack.data['txs']
                pof = pack.data['pof']
                
                q = query("SELECT * FROM blocks ORDER BY height DESC LIMIT 1;", cur)
                prev_hash = hashlib.sha256(
                    calculate_block(q['pof'], q['prevhash'], json.loads(q['transactions'])).encode()
                ).hexdigest()

                calculated = calculate_block(pof, prev_hash, txs)
                block_size = sys.getsizeof(calculated.encode())
                calculated = hashlib.sha256(calculated.encode()).hexdigest()

                if not verify_txs(chain_size(), txs):
                    client.sendall(Packet(Packet.RESPONSE, {
                        "code": 0,
                        "message": "Invalid transactions"
                    }).encode())
                elif not verify_block(pof, prev_hash, txs):
                    client.sendall(Packet(Packet.RESPONSE, {
                        "code": 1,
                        "message": "Invalid block"
                    }).encode())
                else:
                    for tx in txs:
                        if tx['sender'] == "Block Reward" and tx['fee'] == 0:
                            cur.execute(("INSERT INTO transactions (txid, timestamp, amount, fee, "
                                         "key, recipient, sender, confirmed) values (?,?,?,?,?,?,?,1)"), (
                                             tx['txid'], tx['timestamp'], tx['amount'], tx['fee'],
                                             tx['key'], tx['recipient'], tx['sender']
                                         ))
                        else:
                            cur.execute("UPDATE transactions SET confirmed = 1 WHERE txid = ?;", (tx['txid'],))
                    conn.commit()

                    info = (round(time.time()), json.dumps(txs), prev_hash, calculated, pof, get_miner(txs), block_size)
                    run("INSERT INTO blocks (timestamp, transactions, prevhash, hash, pof, miner, size) values (?,?,?,?,?,?,?)",info)
                    client.sendall(Packet(Packet.RESPONSE, info).encode())
                    broadcast(Packet(PTracker.NEWBLOCK, info).encode())                    
    except (ConnectionResetError, ConnectionAbortedError):
        print("Client disconnected")
    finally:
        conn.close()
        trackers = [res for res in trackers if res != client]
        client.close()

print("STARTED")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind((HOST, PORT))
    server.listen()

    while True:
        client, _ = server.accept()
        print("CLIENT CONNECTED")
        Thread(target=handle, args=(client,)).start()