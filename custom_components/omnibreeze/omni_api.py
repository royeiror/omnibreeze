import asyncio
import struct
import hashlib
import base64
import logging
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

_LOGGER = logging.getLogger(__name__)

class OmniBreezeAPI:
    def __init__(self, ip, port, auth_key_b64):
        self.ip = ip
        self.port = port
        self.raw_key = base64.b64decode(auth_key_b64)
        self.hex_key = self.raw_key.hex()
        self.nonce = None
        self.reader = None
        self.writer = None
        self.packet_id = 1
        self.is_connected = False
        self.on_state_update = None

    def _calc_checksum(self, data):
        return sum(data) & 0xFF

    def _create_packet(self, cmd_id, payload=b'', encrypt=False):
        if encrypt and self.nonce:
            cipher = AES.new(self.raw_key, AES.MODE_CBC, iv=self.nonce.encode('utf-8'))
            payload = cipher.encrypt(pad(payload, 16))

        length = len(payload) + 5
        header = b'\xaa\xaa'
        packet_id_bytes = struct.pack('>H', self.packet_id)
        cmd_id_bytes = struct.pack('>H', cmd_id)
        checksum_data = packet_id_bytes + cmd_id_bytes + payload
        checksum = self._calc_checksum(checksum_data)
        full_packet = header + struct.pack('>H', length) + bytes([checksum]) + checksum_data
        self.packet_id = (self.packet_id + 1) & 0xFFFF
        return full_packet

    def _parse_ttlv(self, data):
        results = []
        i = 0
        while i < len(data):
            if i + 2 > len(data): break
            header = struct.unpack('>H', data[i:i+2])[0]
            i += 2
            tag_id = (header >> 3) & 0x1FFF
            tag_type = header & 0x07
            if tag_type in [3, 5]:
                if i + 2 > len(data): break
                length = struct.unpack('>H', data[i:i+2])[0]
                i += 2
                value = data[i:i+length]
                i += length
                results.append((tag_id, value))
            elif tag_type == 2:
                if i + 2 > len(data): break
                value = struct.unpack('>H', data[i:i+2])[0]
                i += 2
                results.append((tag_id, value))
            elif tag_type == 1: results.append((tag_id, True))
            elif tag_type == 0: results.append((tag_id, False))
            else: break
        return results

    def _build_ttlv(self, tag_id, tag_type, value):
        header = ((tag_id & 0x1FFF) << 3) | (tag_type & 0x07)
        data = struct.pack('>H', header)
        if tag_type in [3, 5]:
            if isinstance(value, str): value = value.encode('utf-8')
            data += struct.pack('>H', len(value)) + value
        elif tag_type == 2:
            data += struct.pack('>H', value)
        return data

    async def connect(self):
        try:
            self.reader, self.writer = await asyncio.open_connection(self.ip, self.port)
            self.writer.write(self._create_packet(0x7032))
            await self.writer.drain()
            
            data = await self.reader.read(1024)
            if data.startswith(b'\xaa\xaa'):
                cmd_id = struct.unpack('>H', data[7:9])[0]
                if cmd_id == 0x7033:
                    ttlv = self._parse_ttlv(data[9:])
                    for tid, val in ttlv:
                        if tid == 1:
                            self.nonce = val.decode('utf-8')

            if not self.nonce: return False

            login_str = f"{self.hex_key};{self.nonce}"
            login_hash = hashlib.sha256(login_str.encode('utf-8')).hexdigest()
            login_payload = self._build_ttlv(2, 3, login_hash)
            self.writer.write(self._create_packet(0x7034, login_payload))
            await self.writer.drain()
            
            data = await self.reader.read(1024)
            if data.startswith(b'\xaa\xaa'):
                cmd_id = struct.unpack('>H', data[7:9])[0]
                if cmd_id == 0x7035:
                    self.is_connected = True
                    # Request initial status
                    self.writer.write(self._create_packet(0x7038))
                    await self.writer.drain()
                    
                    asyncio.create_task(self._listen())
                    asyncio.create_task(self._heartbeat())
                    return True
        except Exception as e:
            _LOGGER.error("Connection error: %s", e)
        return False

    async def _listen(self):
        while True:
            try:
                data = await self.reader.read(1024)
                if not data:
                    _LOGGER.warning("Connection lost to %s, reconnecting...", self.ip)
                    break
                
                # Process data
                if data.startswith(b'\xaa\xaa'):
                    # Handle multiple packets in one read
                    while data.startswith(b'\xaa\xaa'):
                        try:
                            length = struct.unpack('>H', data[2:4])[0]
                            cmd_id = struct.unpack('>H', data[7:9])[0]
                            payload = data[9:length+4]
                            
                            # 0x7036 is the response/update from the fan
                            if cmd_id == 0x7036:
                                cipher = AES.new(self.raw_key, AES.MODE_CBC, iv=self.nonce.encode('utf-8'))
                                decrypted = unpad(cipher.decrypt(payload), 16)
                                ttlv = self._parse_ttlv(decrypted)
                                if self.on_state_update:
                                    self.on_state_update(ttlv)
                            
                            data = data[length+4:]
                        except Exception as e:
                            _LOGGER.error("Packet processing error: %s", e)
                            break
            except Exception as e:
                _LOGGER.error("Listen error: %s", e)
                break
        
        self.is_connected = False
        await asyncio.sleep(5)
        asyncio.create_task(self.connect())

    async def _heartbeat(self):
        while self.is_connected:
            try:
                self.writer.write(self._create_packet(0x7037))
                await self.writer.drain()
                await asyncio.sleep(10)
            except: break

    async def send_command(self, dp_id, dp_type, value):
        if not self.is_connected: return False
        cmd_data = self._build_ttlv(dp_id, dp_type, value)
        # 0x7039 is the write command (Control Request)
        packet = self._create_packet(0x7039, cmd_data, encrypt=True)
        self.writer.write(packet)
        await self.writer.drain()
        return True
