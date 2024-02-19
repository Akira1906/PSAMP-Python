import struct

def BOB_hash(key, initval=0xfeedbeef):
    # Built-in parameter: the golden ratio
    golden_ratio = 0x9e3779b9

    # Initialize internal state
    a = b = golden_ratio
    c = initval

    # Mix internal state with each byte of the key
    i = 0
    length = len(key)
    while i + 12 <= length:
        a += struct.unpack("!I", key[i:i+4])[0]
        b += struct.unpack("!I", key[i+4:i+8])[0]
        c += struct.unpack("!I", key[i+8:i+12])[0]
        a, b, c = mix(a, b, c)
        i += 12

    # Mix remaining bytes
    c += length
    if i < length:
        a += struct.unpack("!I", key[i:i+4] + b"\x00\x00\x00")[0]
    if i + 4 < length:
        b += struct.unpack("!I", key[i+4:i+8] + b"\x00\x00")[0]
    if i + 8 < length:
        c += struct.unpack("!I", key[i+8:i+12])[0]
    a, b, c = mix(a, b, c)

    # Return final internal state
    return c

def mix(a, b, c):
    a -= b
    a -= c
    a ^= (c >> 13)
    b -= c
    b -= a
    b ^= (a << 8)
    c -= a
    c -= b
    c ^= (b >> 13)
    a -= b
    a -= c
    a ^= (c >> 12)
    b -= c
    b -= a
    b ^= (a << 16)
    c -= a
    c -= b
    c ^= (b >> 5)
    a -= b
    a -= c
    a ^= (c >> 3)
    b -= c
    b -= a
    b ^= (a << 10)
    c -= a
    c -= b
    c ^= (b >> 15)
    return a, b, c

print(BOB_hash())