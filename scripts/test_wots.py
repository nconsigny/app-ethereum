from ledgerblue.comm import getDongle
import struct
dongle = getDongle(True)
resp = dongle.exchange(bytes([0xE0, 0x06, 0x00, 0x00, 0x00]))
print(f'Version: {resp[1]}.{resp[2]}.{resp[3]}')
path = bytes([5]) + struct.pack('>5I', 0x8000002C, 0x8000003C, 0x80000000, 0, 0)
resp = dongle.exchange(bytes([0xE0, 0x40, 0x00, 0x00, len(path)]) + path)
print(f'pk_seed: {resp[:16].hex()}')
resp = dongle.exchange(bytes([0xE0, 0x40, 0x05, 0x00, 0x00]), timeout=60000)
print(f'WOTS PK[0] from device: {resp[:16].hex()}')
print(f'Python expected:         a05cb90749c70c9824522c8bcc5d986f')
dongle.close()
