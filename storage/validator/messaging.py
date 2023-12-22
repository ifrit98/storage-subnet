from dataclasses import dataclass
from asyncio import StreamReader, StreamWriter
import asyncio

class InvalidData(Exception):
    "Raised when a message contains invalid data"
    pass

def todo():
    pass

### P2P Message structure

STORE = 0x1
REBALANCE = 0x2
VOTE = 0x3

@dataclass
class Message:
    type: int
    nonce: int
    origin: str
    signature: bytes
    data: bytes

    def __init__(self, type: int, nonce: int, origin: str, data: bytes, signature: bytes):
        if len(data) > 256:
            raise InvalidData
        
        self.type = type
        self.nonce = nonce
        self.origin = origin
        self.data = data
        self.signature = signature

    def encode(self) -> bytes:
        encoded = bytes()
        encoded += self.type.to_bytes()
        encoded += self.nonce.to_bytes()
        encoded += self.origin.encode(encoding="ascii")
        encoded += self.signature
        encoded += self.data

        return encoded

    def decode(data: bytes):
        # First byte: type (u8)
        type = data[0]
        # Second byte: nonce (u16)
        nonce = data[1]
        # Bytes 3 to 50: ss58 address
        origin = str(data[2:50])
        # Bytes 51 to 115: signature
        signature = data[50:114]
        # Bytes 116 onward: data
        payload = data[114:]

        if len(payload) > 256:
            raise InvalidData

        return Message(type, nonce, origin, payload, signature)

### P2P Peer Finding
CONNECTION_POOL = []
async def find_peers():
    todo()

async def negotiate():
    todo()

### P2P Message Manager

# Construct a new message to broadcast
async def new_message(message: Message):
    todo()

# We've received a message
async def incoming_message(message):
    print("processing a message")
    message_obj = Message.decode(message)
    print(message_obj.signature)

    await asyncio.sleep(5)
    print("processing done")

    todo()

async def should_deny_connection(writer: StreamWriter) -> bool:
    return False

# Connection made to our TCP server
async def connection_created(reader: StreamReader, writer: StreamWriter):
    peername = writer.get_extra_info('peername')
    print('Connection from {}'.format(peername))

    if (await should_deny_connection(writer)):
        return

    data = await reader.read()
    if len(data) > 370:
        raise InvalidData
    
    await incoming_message(data)

    writer.write(b"ACK")
    await writer.drain()

    writer.close()
    await writer.wait_closed()

# Start TCP server
async def start_messaging_protocol():
    server = await asyncio.start_server(
        client_connected_cb=connection_created,
        host='127.0.0.1', port=8888)

    async with server:
        try:
            await server.serve_forever()
        except:
            print("closed")

asyncio.run(start_messaging_protocol())