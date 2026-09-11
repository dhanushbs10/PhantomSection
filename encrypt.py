import sys

if len(sys.argv) != 2:
    print("Usage: python3 encrypt.py <raw_payload.bin>")
    sys.exit(1)

with open(sys.argv[1], 'rb') as f:
    buf = f.read()

key = 0x55
enc = bytearray([b ^ key for b in buf])

with open('payload.bin', 'wb') as f:
    f.write(enc)

print(f"Encrypted {len(buf)} bytes. Saved to payload.bin (XOR Key: 0x{key:02x})")