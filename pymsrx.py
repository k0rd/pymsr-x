import math
import re
import hashlib
import binascii
import time
import logging
from dataclasses import dataclass
from typing import Optional, Tuple, Dict, List, Any
import usb
import usb.core

# constants for filler data
SEQUENCE_START_BIT = 0b10000000
SEQUENCE_END_BIT = 0b01000000
SEQUENCE_LENGTH_BITS = 0b00111111
ESC = b"\x1b"

# Custom exceptions
class MSRError(Exception):
    """Base class for MSR device errors"""
    pass

class MSRCommunicationError(MSRError):
    """Communication with device failed"""
    pass

class MSRChecksumError(MSRError):
    """Data checksum validation failed"""
    pass

class MSRCardValidationError(MSRError):
    """Card data validation failed"""
    pass

@dataclass
class CardData:
    track1: Optional[str] = None
    track2: Optional[str] = None
    track3: Optional[str] = None
    raw: bool = False

    def __eq__(self, other) -> bool:
        """Compare two CardData objects"""
        if not isinstance(other, CardData):
            return False
        return (self.track1 == other.track1 and
                self.track2 == other.track2 and
                self.track3 == other.track3 and
                self.raw == other.raw)

@dataclass
class ForensicCardData(CardData):
    """Extended card data with forensic information"""
    hashes: Optional[dict] = None
    validation: Optional[dict] = None
    patterns: Optional[dict] = None

    def is_valid(self) -> bool:
        """Check if all track data is valid"""
        return all(self.validation.values()) if self.validation else False

class MSR605X:
    """Represents an MSR605X device with layered API:
    - Transport: HID packet send/recv (64-byte frames)
    - Message: ESC-command framing (send_message/recv_message)
    - Protocol: typed helpers (ping/get_model/led/etc.)
    - Card operations: read_card/write_card (ISO/raw)
    - Forensic analysis: checksums, validation, pattern detection
    """

    def __init__(self, **kwargs):
        if "idVendor" not in kwargs:
            kwargs["idVendor"] = 0x0801
            kwargs["idProduct"] = 0x0003
        self.dev = usb.core.find(**kwargs)
        if self.dev is None:
            raise MSRCommunicationError("MSR605X device not found")
        self.hid_endpoint = None
        self.logger = logging.getLogger("pymsr-x")
        self._closed = False
        self.interface = None

    def connect(self):
        """Establish USB/HID connection to MSR605X."""
        dev = self.dev
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
        dev.set_configuration()
        config = dev.get_active_configuration()
        interface = config.interfaces()[0]
        self.interface = interface
        self.hid_endpoint = interface.endpoints()[0]

    def _make_header(self, start_of_sequence: bool, end_of_sequence: bool, length: int):
        if length < 0 or length > 63:
            raise ValueError("Length must be 0..63")
        header = length
        if start_of_sequence:
            header |= SEQUENCE_START_BIT
        if end_of_sequence:
            header |= SEQUENCE_END_BIT
        return bytes([header])

    def _encapsulate_message(self, message: bytes):
        idx = 0
        while idx < len(message):
            payload = message[idx:idx + 63]
            header = self._make_header(idx == 0, (len(message) - idx) <= 63, len(payload))
            padding = b"\0" * (63 - len(payload))
            yield header + payload + padding
            idx += 63

    def _send_packet(self, packet: bytes):
        self.dev.ctrl_transfer(0x21, 9, wValue=0x0300, wIndex=0, data_or_wLength=packet)

    def _recv_packet(self, **kwargs):
        """Receive a packet with error handling"""
        try:
            if self.hid_endpoint is None:
                raise MSRCommunicationError("Device not connected")

            return bytes(self.hid_endpoint.read(64, **kwargs))
        except usb.core.USBError as error:
            if getattr(error, "errno", None) == 110:
                return None
            raise

    def send_message(self, message: bytes):
        """Send a raw ESC-command message (lib will packetize into 64-byte HID frames)."""
        for packet in self._encapsulate_message(message):
            self._send_packet(packet)

    def recv_message(self, timeout: int = 0) -> Optional[bytes]:
        """Receive a full logical message (handles multi-packet HID framing)."""
        self.logger.debug("Waiting for message with timeout %d", timeout)
        message = b""
        started = False
        start_time = time.time()
        while True:
            packet = self._recv_packet(timeout=timeout)
            if packet is None:
                if not started:
                    return None
                if timeout and (time.time() - start_time) > (timeout / 1000.0):
                    raise MSRCommunicationError("Timed out waiting for full message")
                time.sleep(0.001)
                continue
            header = packet[0]
            payload_length = header & SEQUENCE_LENGTH_BITS
            payload = packet[1:1 + payload_length]
            if header & SEQUENCE_START_BIT:
                started = True
                message = b""
            elif not started:
                continue
            message += payload
            if header & SEQUENCE_END_BIT:
                break
        return message

    # --- Low-level commands (manual mapping) ---
    def read_card(self, raw: bool = False, timeout: int = 0) -> Optional[CardData]:
        cmd = ESC + b"m" if raw else ESC + b"r"
        self.send_message(cmd)
        resp = self.recv_message(timeout=timeout)
        if not resp:
            return None
        last_esc = resp.rfind(b"\x1b")
        payload = resp[:last_esc] if last_esc != -1 else resp
        if raw:
            t1, t2, t3 = self._parse_raw_response(payload)
            return CardData(track1=t1, track2=t2, track3=t3, raw=True)
        else:
            t1, t2, t3 = self._parse_iso_response(payload)
            return CardData(track1=t1, track2=t2, track3=t3, raw=False)

    def write_card(self, card: CardData, raw: bool = False, timeout: int = 0) -> bool:
        if raw:
            block = b""
            if card.track1 is not None:
                t1 = card.track1 if isinstance(card.track1, (bytes, bytearray)) else bytes(card.track1)
                block += ESC + b"\x01" + bytes([len(t1)]) + t1
            if card.track2 is not None:
                t2 = card.track2 if isinstance(card.track2, (bytes, bytearray)) else bytes(card.track2)
                block += ESC + b"\x02" + bytes([len(t2)]) + t2
            if card.track3 is not None:
                t3 = card.track3 if isinstance(card.track3, (bytes, bytearray)) else bytes(card.track3)
                block += ESC + b"\x03" + bytes([len(t3)]) + t3
            frame = ESC + b"n" + ESC + b"s" + block + b"?" + b"\x1c"
            self.send_message(frame)
            r = self.recv_message(timeout=timeout)
            return bool(r and r.startswith(ESC + b"0"))
        else:
            block = b""
            if card.track1 is not None:
                b1 = card.track1.encode() if isinstance(card.track1, str) else bytes(card.track1)
                block += ESC + b"\x01" + b1
            if card.track2 is not None:
                b2 = card.track2.encode() if isinstance(card.track2, str) else bytes(card.track2)
                block += ESC + b"\x02" + b2
            if card.track3 is not None:
                b3 = card.track3.encode() if isinstance(card.track3, str) else bytes(card.track3)
                block += ESC + b"\x03" + b3
            frame = ESC + b"w" + ESC + b"s" + block + b"?" + b"\x1c"
            self.send_message(frame)
            r = self.recv_message(timeout=timeout)
            return bool(r and r.startswith(ESC + b"0"))

    def reset(self):
        self.send_message(ESC + b"a")

    def get_firmware_version(self) -> Optional[str]:
        self.send_message(ESC + b"v")
        r = self.recv_message()
        if not r:
            return None
        if r.startswith(ESC):
            return r[1:].decode(errors="ignore")
        return r.decode(errors="ignore")

    def ping(self, timeout: int = 500) -> bool:
        self.send_message(ESC + b"e")
        resp = self.recv_message(timeout=timeout)
        return bool(resp and resp.startswith(ESC + b"y"))

    def get_model(self, timeout: int = 500) -> Optional[str]:
        self.send_message(ESC + b"t")
        r = self.recv_message(timeout=timeout)
        if not r:
            return None
        if r.startswith(ESC):
            return r[1:].decode(errors="ignore")
        return r.decode(errors="ignore")

    def led(self, which: str, on: bool = True):
        mapping = {
            ("all", True): b"\x81",
            ("all", False): b"\x80",
            ("green", True): b"\x83",
            ("yellow", True): b"\x84",
            ("red", True): b"\x85",
            }
        key = (which.lower(), on)
        cmd = mapping.get(key)
        if cmd is None:
            raise ValueError("unknown led control")
        self.send_message(ESC + cmd)

    def set_hico(self) -> bool:
        self.send_message(ESC + b"x")
        r = self.recv_message(timeout=200)
        return bool(r and r.startswith(ESC + b"0"))

    def set_loco(self) -> bool:
        self.send_message(ESC + b"y")
        r = self.recv_message(timeout=200)
        return bool(r and r.startswith(ESC + b"0"))

    def erase(self, select_byte: int = 0b00000111) -> bool:
        self.send_message(ESC + b"c" + bytes([select_byte]))
        r = self.recv_message(timeout=500)
        return bool(r and r.startswith(ESC + b"0"))

    def set_leading_zeros(self, track1_3_zeros: int, track2_zeros: int) -> bool:
        """Set leading zeros for tracks (command 12 in manual)"""
        if not (0 <= track1_3_zeros <= 255 and 0 <= track2_zeros <= 255):
            raise ValueError("Zero values must be between 0 and 255")
        self.send_message(ESC + b"z" + bytes([track1_3_zeros, track2_zeros]))
        r = self.recv_message(timeout=200)
        return bool(r and r.startswith(ESC + b"0"))

    def get_leading_zeros(self) -> Optional[Tuple[int, int]]:
        """Get current leading zero settings (command 13 in manual)"""
        self.send_message(ESC + b"l")  # Note: manual says ESC+1 but hex is 1B6C
        r = self.recv_message(timeout=200)
        if r and len(r) >= 3 and r.startswith(ESC):
            return r[1], r[2]
        return None

    def set_bpi(self, track: int, density: int) -> bool:
        """Set bits per inch for a track (command 15 in manual)"""
        if track == 2:
            cmd = ESC + b"b" + (b"\xD2" if density == 210 else b"\x4B")
        elif track == 1:
            cmd = ESC + b"b" + (b"\xA1" if density == 210 else b"\xA0")
        elif track == 3:
            cmd = ESC + b"b" + (b"\xC1" if density == 210 else b"\xC0")
        else:
            raise ValueError("Track must be 1, 2, or 3")

        self.send_message(cmd)
        r = self.recv_message(timeout=200)
        return bool(r and r.startswith(ESC + b"0"))

    def set_bpc(self, track1_bits: int, track2_bits: int, track3_bits: int) -> bool:
        """Set bits per character for tracks (command 20 in manual)"""
        if not all(5 <= bits <= 8 for bits in [track1_bits, track2_bits, track3_bits]):
            raise ValueError("Bits per character must be between 5 and 8")
        self.send_message(ESC + b"o" + bytes([track1_bits, track2_bits, track3_bits]))
        r = self.recv_message(timeout=200)
        return bool(r and r.startswith(ESC + b"0"))

    def get_coercivity_status(self) -> Optional[str]:
        """Get current coercivity status (Hi-Co or Lo-Co)"""
        self.send_message(ESC + b"d")
        r = self.recv_message(timeout=200)
        if r == ESC + b"H":
            return "Hi-Co"
        elif r == ESC + b"L":
            return "Lo-Co"
        return None

    def sensor_test(self) -> bool:
        """Test card sensor (command 10 in manual)"""
        self.send_message(ESC + b"\x86")
        r = self.recv_message(timeout=5000)  # Longer timeout for card swipe
        return bool(r and r == ESC + b"0")

    def ram_test(self) -> bool:
        """Test device RAM (command 11 in manual)"""
        self.send_message(ESC + b"\x87")
        r = self.recv_message(timeout=200)
        return bool(r and r == ESC + b"0")

    # --- Card operations ---

    def _calculate_lrc(self, data: bytes, bits_per_char: int = 8) -> int:
        """Calculate Longitudinal Redundancy Check for raw data"""
        if bits_per_char not in [5, 6, 7, 8]:
            raise ValueError("Bits per character must be 5, 6, 7, or 8")

        lrc = 0
        for byte in data:
            lrc ^= byte

        # Mask to appropriate number of bits
        mask = (1 << bits_per_char) - 1
        return lrc & mask

    def _validate_track_data(self, track_num: int, data: str) -> bool:
        """Validate track data against known formats and patterns"""
        if not data:
            return False

        # Track-specific validation
        if track_num == 1:
            # Track 1 should start with '%' and end with '?'
            if not data.startswith('%') or not data.endswith('?'):
                return False

        elif track_num in [2, 3]:
            # Tracks 2 and 3 should start with ';' and end with '?'
            if not data.startswith(';') or not data.endswith('?'):
                return False

        return True

    def _calculate_data_hash(self, data: str, algorithm: str = "md5") -> str:
        """Calculate hash of track data for forensic identification"""
        if not data:
            return ""

        data_bytes = data.encode('utf-8')
        if algorithm.lower() == "md5":
            return hashlib.md5(data_bytes).hexdigest()
        elif algorithm.lower() == "sha1":
            return hashlib.sha1(data_bytes).hexdigest()
        elif algorithm.lower() == "sha256":
            return hashlib.sha256(data_bytes).hexdigest()
        else:
            raise ValueError("Unsupported hash algorithm")

    def _detect_data_patterns(self, track_data: dict) -> dict:
        """Detect patterns in track data for forensic analysis"""
        patterns = {}

        for track, data in track_data.items():
            if not data:
                continue

            patterns[track] = {
                "credit_card": re.match(r"^%B\d{16,19}\^", data) is not None,
                "aba_number": re.match(r"^;(\d{16,19})=", data) is not None,
                "expiration_date": re.search(r"=(\d{2})(\d{2})", data) is not None,
                "service_code": re.search(r"=...\?", data) is not None,
            }

        return patterns

    def forensic_read_card(self, timeout: int = 0) -> Optional[ForensicCardData]:
        """Read card with enhanced forensic analysis"""
        card_data = self.read_card(raw=False, timeout=timeout)
        if not card_data:
            return None

        # Calculate hashes for each track
        hashes = {
            "track1": self._calculate_data_hash(card_data.track1) if card_data.track1 else "",
            "track2": self._calculate_data_hash(card_data.track2) if card_data.track2 else "",
            "track3": self._calculate_data_hash(card_data.track3) if card_data.track3 else "",
        }

        # Validate track data
        validation = {
            "track1": self._validate_track_data(1, card_data.track1) if card_data.track1 else False,
            "track2": self._validate_track_data(2, card_data.track2) if card_data.track2 else False,
            "track3": self._validate_track_data(3, card_data.track3) if card_data.track3 else False,
        }

        # Detect patterns
        track_data = {
            "track1": card_data.track1,
            "track2": card_data.track2,
            "track3": card_data.track3,
        }
        patterns = self._detect_data_patterns(track_data)

        return ForensicCardData(
            track1=card_data.track1,
            track2=card_data.track2,
            track3=card_data.track3,
            raw=card_data.raw,
            hashes=hashes,
            validation=validation,
            patterns=patterns
        )

    def write_card_with_validation(self, card: CardData, max_retries: int = 3, timeout: int = 0) -> bool:
        """Write card with validation by reading back and comparing"""
        for attempt in range(max_retries):
            if self.write_card(card, raw=card.raw, timeout=timeout):
                # Read back to verify
                written_data = self.read_card(raw=card.raw, timeout=timeout)
                if written_data and written_data == card:
                    return True
        return False

    def _parse_iso_response(self, data: bytes) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        try:
            # Find the start of data block (after <ESC>s)
            start_idx = data.find(b"\x1b\x73")
            if start_idx == -1:
                start_idx = 0
            else:
                start_idx += 2  # Skip past <ESC>s

            payload = data[start_idx:]
            t = {1: None, 2: None, 3: None}
            i = 0

            while i < len(payload):
                if payload[i] == 0x1B:  # ESC character
                    i += 1
                    if i >= len(payload):
                        break

                    track_num = payload[i]
                    if track_num in (1, 2, 3):
                        i += 1
                        start = i
                        # Read until field separator (0x3F) or end sentinel (0x1C)
                        while i < len(payload) and payload[i] not in (0x3F, 0x1C):
                            i += 1

                        if track_num == 3:
                            # Special handling for track 3 - may have different encoding
                            track_data = payload[start:i].decode('latin-1').strip()
                        else:
                            track_data = payload[start:i].decode('ascii', errors='ignore').strip()

                        # Remove any trailing question marks or other separators
                        track_data = track_data.rstrip('?')
                        t[track_num] = track_data
                    else:
                        i += 1
                else:
                    i += 1

            return t[1], t[2], t[3]
        except (IndexError, UnicodeDecodeError) as e:
            self.logger.error("Failed to parse ISO response: %s", e)
            raise MSRCommunicationError("Failed to parse ISO response") from e

    def _process_track3_data(self, raw_data: bytes) -> str:
        """
        Process track 3 raw data based on the bit orientation described in the manual (page 15).
        This converts the raw bytes to the appropriate character representation.
        """
        if not raw_data:
            return ""

        # Implement the bit manipulation described in the manual for track 3
        # This is a simplified version - anyone who actually uses it is invited to fix via pull request
        result = []
        for byte in raw_data:
            if 0x20 <= byte <= 0x7E:
                result.append(chr(byte))
            else:
                # Handle special characters or binary data
                result.append(f"[{byte:02X}]")
        return ''.join(result)


    def _parse_raw_response(self, data: bytes) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes]]:
        try:
            # Find the start of data block (after <ESC>s)
            start_idx = data.find(b"\x1b\x73")
            if start_idx == -1:
                start_idx = 0
            else:
                start_idx += 2  # Skip past <ESC>s

            payload = data[start_idx:]
            t = {1: None, 2: None, 3: None}
            i = 0

            while i < len(payload):
                if payload[i] == 0x1B:  # ESC character
                    i += 1
                    if i >= len(payload):
                        break

                    track_num = payload[i]
                    if track_num in (1, 2, 3):
                        i += 1
                        if i >= len(payload):
                            break

                        length = payload[i]
                        i += 1

                        if i + length > len(payload):
                            # Not enough data
                            break

                        track_data = payload[i:i+length]

                        if track_num == 3:
                            track_data=self._process_track3_data(track_data)


                        t[track_num] = track_data
                        i += length
                    else:
                        i += 1
                else:
                    i += 1

            return t[1], t[2], t[3]
        except (IndexError, ValueError) as e:
            self.logger.error("Failed to parse RAW response: %s", e)
            raise MSRCommunicationError("Failed to parse RAW response") from e



    # --- Forensic Analysis Methods ---

    def discover_card_settings(self, timeout: int = 0) -> Optional[dict]:
        """
        Dynamically discover BPI and track settings by analyzing raw card data.
        Returns a dictionary with discovered settings for forensic analysis.
        """
        # Read card in raw mode to get the fundamental data
        raw_data = self.read_card(raw=True, timeout=timeout)
        if not raw_data:
            return None

        settings = {
            'tracks_present': [],
            'estimated_bpi': {},
            'data_density': {},
            'encoding_characteristics': {}
        }

        # Check which tracks are present
        for i, track_data in enumerate([raw_data.track1, raw_data.track2, raw_data.track3], 1):
            if track_data:
                settings['tracks_present'].append(i)

                # Estimate BPI based on data characteristics
                bpi_estimate = self._estimate_bpi(track_data, i)
                settings['estimated_bpi'][f'track{i}'] = bpi_estimate

                # Calculate data density (bits per character equivalent)
                density_info = self._calculate_data_density(track_data, i)
                settings['data_density'][f'track{i}'] = density_info

                # Analyze encoding characteristics
                encoding_info = self._analyze_encoding_characteristics(track_data, i)
                settings['encoding_characteristics'][f'track{i}'] = encoding_info

        return settings

    def _estimate_bpi(self, track_data: bytes, track_num: int) -> str:
        """
        Estimate BPI based on data patterns and characteristics.
        This is a heuristic approach based on common card encoding practices.
        """
        if not track_data:
            return "unknown"

        # Calculate basic statistics
        data_length = len(track_data)

        # Track-specific BPI characteristics
        if track_num == 1:
            # Track 1 is typically 210 BPI with 7-bit characters
            return "210 BPI (likely)"
        elif track_num == 2:
            # Track 2 can be 75 or 210 BPI
            # Shorter data suggests 75 BPI, longer suggests 210 BPI
            if data_length < 20:
                return "75 BPI (likely)"
            else:
                return "210 BPI (likely)"
        elif track_num == 3:
            # Track 3 is typically 210 BPI
            return "210 BPI (likely)"

        return "unknown"

    def _calculate_data_density(self, track_data: bytes, track_num: int) -> dict:
        """
        Calculate data density metrics for forensic analysis.
        """
        if not track_data:
            return {}

        data_length = len(track_data)

        # Calculate entropy (measure of randomness)
        entropy = self._calculate_entropy(track_data)

        # Count different character types
        printable_chars = sum(1 for byte in track_data if 32 <= byte <= 126)
        control_chars = sum(1 for byte in track_data if byte < 32)
        high_chars = sum(1 for byte in track_data if byte > 126)

        # Common patterns in magnetic stripe data
        sentinel_patterns = {
            1: (b'%', b'?'),  # Track 1 typically starts with % and ends with ?
            2: (b';', b'?'),  # Track 2 typically starts with ; and ends with ?
            3: (b';', b'?')   # Track 3 typically starts with ; and ends with ?
        }

        start_sentinel, end_sentinel = sentinel_patterns.get(track_num, (None, None))
        has_start_sentinel = start_sentinel and track_data.startswith(start_sentinel)
        has_end_sentinel = end_sentinel and track_data.endswith(end_sentinel)

        return {
            'length': data_length,
            'entropy': entropy,
            'printable_chars': printable_chars,
            'control_chars': control_chars,
            'high_chars': high_chars,
            'has_start_sentinel': has_start_sentinel,
            'has_end_sentinel': has_end_sentinel,
            'printable_ratio': printable_chars / data_length if data_length > 0 else 0
        }

    def _analyze_encoding_characteristics(self, track_data: bytes, track_num: int) -> dict:
        """
        Analyze encoding characteristics of the track data.
        """
        if not track_data:
            return {}

        # Check for common encoding patterns
        is_ascii = all(byte < 128 for byte in track_data)
        is_binary = not is_ascii

        # Check for common magnetic stripe encoding patterns
        has_lrc = False
        if len(track_data) > 2:
            # Simple LRC check (longitudinal redundancy check)
            lrc = 0
            for byte in track_data[:-1]:
                lrc ^= byte
            has_lrc = (lrc == track_data[-1])

        # Check for parity patterns (odd parity common in mag stripes)
        odd_parity_count = 0
        for byte in track_data:
            # Count bits set to 1
            bits_set = bin(byte).count('1')
            if bits_set % 2 == 1:  # Odd parity
                odd_parity_count += 1

        odd_parity_ratio = odd_parity_count / len(track_data) if track_data else 0

        return {
            'is_ascii': is_ascii,
            'is_binary': is_binary,
            'has_lrc': has_lrc,
            'odd_parity_ratio': odd_parity_ratio,
            'likely_iso_format': has_lrc and odd_parity_ratio > 0.7
        }

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate the Shannon entropy of a byte sequence.
        Higher values indicate more randomness.
        """
        if not data:
            return 0.0

        # Count frequency of each byte value
        frequency = [0] * 256
        for byte in data:
            frequency[byte] += 1

        # Calculate entropy
        entropy = 0.0
        for count in frequency:
            if count > 0:
                probability = count / len(data)
                entropy -= probability * math.log2(probability)

        return entropy

    def detect_encoding_scheme(self, track_data: bytes, track_num: int) -> str:
        """
        Detect the likely encoding scheme used for the track data.
        """
        if not track_data:
            return "unknown"

        characteristics = self._analyze_encoding_characteristics(track_data, track_num)

        if characteristics.get('likely_iso_format', False):
            return "ISO 7811 format"

        # Check for common proprietary formats
        if track_num == 2 and len(track_data) == 16:
            return "Possible ABA format"

        # Check for simple ASCII encoding
        if characteristics.get('is_ascii', False):
            printable_ratio = self._calculate_data_density(track_data, track_num).get('printable_ratio', 0)
            if printable_ratio > 0.8:
                return "ASCII text"

        return "Proprietary or unknown format"

    def generate_forensic_report(self, timeout: int = 0) -> Optional[dict]:
        """
        Generate a comprehensive forensic report for a card.
        """
        card_data = self.read_card(raw=False, timeout=timeout)
        if not card_data:
            return None

        raw_data = self.read_card(raw=True, timeout=timeout)
        settings = self.discover_card_settings(timeout=timeout)

        report = {
            'card_data': {
                'track1': card_data.track1,
                'track2': card_data.track2,
                'track3': card_data.track3,
                'raw_mode': card_data.raw
            },
            'settings': settings,
            'card_type': self.identify_card_type(card_data),
            'encoding_schemes': {},
            'anomalies': [],
            'timestamps': {
                'analysis_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'timestamp': time.time()
            }
        }

        # Add encoding scheme detection for each track
        for i, track_data in enumerate([raw_data.track1, raw_data.track2, raw_data.track3], 1):
            if track_data:
                scheme = self.detect_encoding_scheme(track_data, i)
                report['encoding_schemes'][f'track{i}'] = scheme

        # Check for anomalies
        report['anomalies'] = self._detect_anomalies(card_data, raw_data, settings)

        return report

    def _detect_anomalies(self, card_data, raw_data, settings) -> list:
        """
        Detect anomalies in the card data for forensic investigation.
        """
        anomalies = []

        # Check for track inconsistencies
        tracks_present = settings.get('tracks_present', [])
        if len(tracks_present) == 0:
            anomalies.append("No tracks found on card")

        # Check for unexpected track combinations
        if 2 in tracks_present and 1 not in tracks_present:
            anomalies.append("Track 2 present without Track 1 (unusual for payment cards)")

        # Check for data format inconsistencies
        for i in tracks_present:
            track_key = f'track{i}'
            encoding_info = settings.get('encoding_characteristics', {}).get(track_key, {})

            if not encoding_info.get('has_start_sentinel', False):
                anomalies.append(f"Track {i} missing start sentinel")

            if not encoding_info.get('has_end_sentinel', False):
                anomalies.append(f"Track {i} missing end sentinel")

            if encoding_info.get('is_binary', False) and encoding_info.get('printable_ratio', 0) > 0.5:
                anomalies.append(f"Track {i} has mixed binary and text data (suspicious)")

        return anomalies

    def identify_card_type(self, card_data):
        """
        Identify the type of card based on track data patterns.
        Returns a dictionary with card type and properties.
        """
        results = {
            'card_type': 'unknown',
            'properties': {},
            'confidence': 0
        }

        # Check for credit/debit card patterns
        if self._is_credit_card(card_data):
            results['card_type'] = 'credit/debit'
            results['properties'] = self._extract_credit_card_properties(card_data)
            results['confidence'] = 85

        # Check for gift card patterns
        elif self._is_gift_card(card_data):
            results['card_type'] = 'gift'
            results['properties'] = self._extract_gift_card_properties(card_data)
            results['confidence'] = 75

        # Check for access control card patterns
        elif self._is_access_card(card_data):
            results['card_type'] = 'access_control'
            results['properties'] = self._extract_access_card_properties(card_data)
            results['confidence'] = 80

        # Check for hotel key card patterns
        elif self._is_hotel_key(card_data):
            results['card_type'] = 'hotel_key'
            results['properties'] = self._extract_hotel_key_properties(card_data)
            results['confidence'] = 70

        return results

    def _is_credit_card(self, card_data):
        """Check if card data matches credit/debit card patterns"""
        # Standard credit card patterns
        credit_card_patterns = [
            # Track 1: Starts with %B followed by 16-19 digits
            r'^%B\d{16,19}\^',
            # Track 2: Starts with ; followed by 16-19 digits and =
            r'^;\d{16,19}=',
            # Contains expiration date (YYMM) and service code
            r'=\d{4}\d{3}'
        ]

        for track in [card_data.track1, card_data.track2]:
            if track:
                for pattern in credit_card_patterns:
                    if re.search(pattern, track):
                        return True
        return False

    def _extract_credit_card_properties(self, card_data):
        """Extract properties from credit/debit card data"""
        properties = {}

        # Extract from Track 1
        if card_data.track1:
            match = re.search(r'^%B(\d{16,19})\^([^^]+)\^(\d{4})(\d{3})?', card_data.track1)
            if match:
                properties['pan'] = match.group(1)
                properties['cardholder_name'] = match.group(2).replace('/', ' ')
                properties['expiration_date'] = match.group(3)  # YYMM format
                if match.group(4):
                    properties['service_code'] = match.group(4)

                # Identify issuer based on PAN
                properties['issuer'] = self._identify_issuer(match.group(1))

        # Extract from Track 2
        if card_data.track2:
            match = re.search(r'^;(\d{16,19})=(\d{4})(\d{3})?', card_data.track2)
            if match:
                properties['pan'] = properties.get('pan', match.group(1))
                properties['expiration_date'] = properties.get('expiration_date', match.group(2))
                if match.group(3) and 'service_code' not in properties:
                    properties['service_code'] = match.group(3)

        return properties

    def _identify_issuer(self, pan):
        """Identify card issuer based on PAN (Primary Account Number)"""
        # IIN (Issuer Identification Number) ranges
        iin_ranges = {
            'Visa': r'^4',
            'MasterCard': r'^5[1-5]',
            'American Express': r'^3[47]',
            'Discover': r'^6(?:011|5)',
            'Diners Club': r'^3(?:0[0-5]|[68])',
            'JCB': r'^(?:2131|1800|35)'
        }

        for issuer, pattern in iin_ranges.items():
            if re.match(pattern, pan):
                return issuer
        return 'Unknown'

    def _is_gift_card(self, card_data):
        """Check if card data matches gift card patterns"""
        gift_card_indicators = [
            # Often has fixed value prefixes or specific formats
            r'GIFT',
            r'STORECARD',
            r'PREPAID',
            r'GV\d{16}',  # Gift card with 16 digits
            r'GC\d{16}',  # Gift card with 16 digits
        ]

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                for indicator in gift_card_indicators:
                    if re.search(indicator, track, re.IGNORECASE):
                        return True
        return False

    def _extract_gift_card_properties(self, card_data):
        """Extract properties from gift card data"""
        properties = {}

        # Try to extract card number
        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                # Look for long digit sequences (typical of gift card numbers)
                match = re.search(r'(\d{16,20})', track)
                if match:
                    properties['card_number'] = match.group(1)
                    break

        # Try to identify retailer
        retailer_patterns = {
            'Amazon': r'AMZN|AMAZON',
            'Walmart': r'WALMARTSHOPCARD',
            'Target': r'TARGET',
            'Starbucks': r'STARBUCKS|SBUX',
            'Apple': r'APPLE|ITUNES',
        }

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                for retailer, pattern in retailer_patterns.items():
                    if re.search(pattern, track, re.IGNORECASE):
                        properties['retailer'] = retailer
                        break

        return properties

    def _is_access_card(self, card_data):
        """Check if card data matches access control card patterns"""
        access_card_indicators = [
            # Often has facility code and card number
            r'\bFC\d+\b',
            r'\bFAC\d+\b',
            r'\bCN\d+\b',
            # Common access control formats
            r';\d+\+?\d+?\?',
            # HID corporate format
            r'^\?~',
        ]

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                for indicator in access_card_indicators:
                    if re.search(indicator, track):
                        return True
        return False

    def _extract_access_card_properties(self, card_data):
        """Extract properties from access control card data"""
        properties = {}

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                # Extract facility code
                fc_match = re.search(r'\bFAC?(\d+)\b', track)
                if fc_match:
                    properties['facility_code'] = fc_match.group(1)

                # Extract card number
                cn_match = re.search(r'\bCN(\d+)\b', track)
                if cn_match:
                    properties['card_number'] = cn_match.group(1)

                # Try to extract standard format (e.g.,  facility code + card number)
                format_match = re.search(r'(\d+)\+?(\d+)', track)
                if format_match:
                    properties['facility_code'] = properties.get('facility_code', format_match.group(1))
                    properties['card_number'] = properties.get('card_number', format_match.group(2))

        return properties

    def _is_hotel_key(self, card_data):
        """Check if card data matches hotel key card patterns"""
        hotel_key_indicators = [
            # Often contains room number and dates
            r'RM\d+',
            r'CHECKIN',
            r'CHECKOUT',
            r'\d{6,8}',  # Date in YYMMDD or YYYYMMDD format
            # Common hotel chains
            r'HILTON|MARRIOTT|HYATT|SHERATON|WESTIN',
        ]

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                for indicator in hotel_key_indicators:
                    if re.search(indicator, track, re.IGNORECASE):
                        return True
        return False

    def _extract_hotel_key_properties(self, card_data):
        """Extract properties from hotel key card data"""
        properties = {}

        for track in [card_data.track1, card_data.track2, card_data.track3]:
            if track:
                # Extract room number
                rm_match = re.search(r'RM(\d+)', track, re.IGNORECASE)
                if rm_match:
                    properties['room_number'] = rm_match.group(1)

                # Extract check-in/check-out dates
                date_match = re.search(r'(\d{6,8})', track)
                if date_match:
                    date_str = date_match.group(1)
                    if len(date_str) == 6:  # YYMMDD
                        properties['date'] = f"20{date_str[0:2]}-{date_str[2:4]}-{date_str[4:6]}"
                    elif len(date_str) == 8:  # YYYYMMDD
                        properties['date'] = f"{date_str[0:4]}-{date_str[4:6]}-{date_str[6:8]}"

                # Identify hotel chain
                hotel_chains = {
                    'Hilton': r'HILTON',
                    'Marriott': r'MARRIOTT',
                    'Hyatt': r'HYATT',
                    'Sheraton': r'SHERATON',
                    'Westin': r'WESTIN',
                }

                for chain, pattern in hotel_chains.items():
                    if re.search(pattern, track, re.IGNORECASE):
                        properties['hotel_chain'] = chain
                        break

        return properties

    def calculate_data_entropy(self, data):
        """
        Calculate the Shannon entropy of the card data.
        Higher entropy suggests encrypted or random data.
        Lower entropy suggests human-readable data.
        """
        if not data:
            return 0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)

        return entropy

    def detect_encoding_type(self, card_data):
        """
        Detect the encoding type of the card data.
        Returns a dictionary with encoding information.
        """
        results = {
            'encoding': 'unknown',
            'confidence': 0,
            'notes': ''
        }

        # Check for ASCII encoding
        ascii_chars = sum(1 for c in (card_data.track1 or '') +
                         (card_data.track2 or '') +
                         (card_data.track3 or '')
                         if ord(c) < 128)
        total_chars = len((card_data.track1 or '') +
                         (card_data.track2 or '') +
                         (card_data.track3 or ''))

        if total_chars > 0 and ascii_chars / total_chars > 0.95:
            results['encoding'] = 'ASCII'
            results['confidence'] = 90
            results['notes'] = 'Primarily ASCII characters'

        # Check for binary data (high entropy)
        elif self.calculate_data_entropy((card_data.track1 or '') +
                                       (card_data.track2 or '') +
                                       (card_data.track3 or '')) > 6:
            results['encoding'] = 'Binary/Encrypted'
            results['confidence'] = 75
            results['notes'] = 'High entropy suggests encrypted or binary data'

        return results

    def close(self) -> None:
        """Close the device connection"""
        if hasattr(self, 'interface') and self.interface and self.interface.is_kernel_driver_active(0):
            try:
                self.dev.attach_kernel_driver(0)
            except usb.core.USBError as e:
                self.logger.warning("Could not reattach kernel driver: %s", e)

        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
