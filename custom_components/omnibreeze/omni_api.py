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

        packet_id_bytes = struct.pack('>H', self.packet_id)
        cmd_id_bytes = struct.pack('>H', cmd_id)
        length = len(payload) + 5
        header = b'\xaa\xaa' + struct.pack('>H', length)
        checksum_data = packet_id_bytes + cmd_id_bytes + payload
        checksum = self._calc_checksum(checksum_data)
        
        full_packet = header + struct.pack('B', checksum) + packet_id_bytes + cmd_id_bytes + payload
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
                # Handle variable length int
                length_prefix = data[i]
                i += 1
                value_bytes = data[i:i+length_prefix+1]
                i += length_prefix + 1
                val = int.from_bytes(value_bytes, 'big')
                results.append((tag_id, val))
            elif tag_type == 1: results.append((tag_id, True))
            elif tag_type == 0: results.append((tag_id, False))
            else: break
        return results

    def _build_int_payload(self, val):
        if val == 0: return b'\x00\x00'
        b = struct.pack('>Q', val)
        for i in range(8):
            if b[i] != 0:
                data = b[i:]
                return struct.pack('B', len(data) - 1) + data
        return b'\x00\x00'

    async def _send_magic_token(self):
        # The magic token found in PCAP (28 bytes)
        token_hex = "2aae26c2be5b12998a3bba3fbf09d76773d274386ceb349e4dd3f6f6"
        token = bytes.fromhex(token_hex)
        header = struct.pack('>H', (502 << 3) | 3) # Tag 502, Type 3 (Bytes)
        payload = header + struct.pack('>H', len(token)) + token
        packet = self._create_packet(0x0011, payload)
        self.writer.write(packet)
        await self.writer.drain()

    async def _request_info(self):
        # 0x0013 requests full state from fan
        packet = self._create_packet(0x0013)
        self.writer.write(packet)
        await self.writer.drain()

    async def async_login(self):
        """Perform the full handshake and login."""
        try:
            self.reader, self.writer = await asyncio.open_connection(self.ip, 6607)
            
            # 1. Hello
            self.writer.write(self._create_packet(0x7032))
            await self.writer.drain()
            
            # 2. Receive Nonce
            data = await asyncio.wait_for(self.reader.read(1024), timeout=5.0)
            if not data.startswith(b'\xaa\xaa'):
                return False
            cmd_id = struct.unpack('>H', data[7:9])[0]
            if cmd_id != 0x7033:
                return False
            self.nonce = data[13:29].decode('utf-8')
            
            # 3. Login
            login_str = f"{self.hex_key.upper()};{self.nonce}"
            login_hash = hashlib.sha256(login_str.encode('utf-8')).hexdigest()
            header = struct.pack('>H', (2 << 3) | 3)
            payload = header + struct.pack('>H', len(login_hash)) + login_hash.encode('utf-8')
            self.writer.write(self._create_packet(0x7034, payload))
            await self.writer.drain()
            
            # 4. Success?
            data = await asyncio.wait_for(self.reader.read(1024), timeout=5.0)
            if not data.startswith(b'\xaa\xaa'):
                return False
            cmd_id = struct.unpack('>H', data[7:9])[0]
            if cmd_id == 0x7035:
                self.packet_id = 1
                self.is_connected = True
                await self._send_magic_token()
                await self._request_info()
                asyncio.create_task(self._listen())
                asyncio.create_task(self._heartbeat())
                return True
            return False
        except Exception as e:
            _LOGGER.error("[%s] Login failed: %s", self.ip, e)
            return False

    async def async_set_power(self, state: bool):
        """Set fan power state."""
        val = 1 if state else 0
        payload = struct.pack('>H', (576 << 3) | 2) + self._build_int_payload(val)
        packet = self._create_packet(0x7039, payload, encrypt=True)
        self.writer.write(packet)
        await self.writer.drain()

    async def async_set_oscillation(self, state: bool):
        """Set fan oscillation state."""
        header = (257 << 3) | (1 if state else 0)
        payload = struct.pack('>H', header)
        packet = self._create_packet(0x7039, payload, encrypt=True)
        self.writer.write(packet)
        await self.writer.drain()

    async def async_set_speed(self, speed: int):
        """Set fan speed (1-12)."""
        payload = struct.pack('>H', (258 << 3) | 2) + self._build_int_payload(speed)
        packet = self._create_packet(0x7039, payload, encrypt=True)
        self.writer.write(packet)
        await self.writer.drain()

    async def _listen(self):
        while self.is_connected:
            try:
                data = await self.reader.read(1024)
                if not data: break
                if data.startswith(b'\xaa\xaa'):
                    cmd_id = struct.unpack('>H', data[7:9])[0]
                    if cmd_id == 0x7036: # Status update
                        payload = data[9:]
                        cipher = AES.new(self.raw_key, AES.MODE_CBC, iv=self.nonce.encode('utf-8'))
                        try:
                            decrypted = unpad(cipher.decrypt(payload), 16)
                            ttlv = self._parse_ttlv(decrypted)
                            if self.on_state_update:
                                self.on_state_update(ttlv)
                        except: pass
            except: break
        self.is_connected = False

    async def _heartbeat(self):
        while self.is_connected:
            try:
                # Heartbeat 0x7037 should be encrypted empty payload
                self.writer.write(self._create_packet(0x7037, encrypt=True))
                await self.writer.drain()
                await asyncio.sleep(10)
            except: break
