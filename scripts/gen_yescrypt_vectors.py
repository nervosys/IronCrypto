"""yescrypt and $7$ scrypt hashes from libxcrypt, the crypt(3) of current
Linux distributions.

    python3 -I scripts/gen_yescrypt_vectors.py > testvectors/yescrypt-libxcrypt.json

Run on Linux with libxcrypt (libcrypt.so.1), which carries Openwall's
yescrypt. Python 3.13 dropped its crypt module, so libxcrypt is called
through ctypes. Each case is a password, the hash string libxcrypt's crypt()
returned for a setting, and whether crypt() reproduces that hash for the
password -- the test of a verifier.

Settings: libxcrypt's own crypt_gensalt for "$y$" at several costs, and
settings written here, with the parameter encoding transcribed from
yescrypt-common.c's encode64_uint32, to reach what crypt_gensalt does not
vary: r, p, t, the WORM and classic flavors, and the "$7$" scrypt format.
Whatever this script writes, libxcrypt decodes and hashes; a mistake here
gives a different setting, never a wrong vector. Salts are fixed bytes so
the file is reproducible.
"""

import ctypes
import hashlib
import json
import sys

lib = ctypes.CDLL("libcrypt.so.1")
lib.crypt.restype = ctypes.c_char_p
lib.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.crypt_gensalt.restype = ctypes.c_char_p
lib.crypt_gensalt.argtypes = [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_int]

ITOA64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def enc_u32(src, minimum):
    """yescrypt-common.c encode64_uint32."""
    start, end, chars, bits = 0, 47, 1, 0
    src -= minimum
    while True:
        count = (end + 1 - start) << bits
        if src < count:
            break
        start = end + 1
        end = start + (62 - end) // 2
        src -= count
        chars += 1
        bits += 6
    out = bytes([ITOA64[start + (src >> bits)]])
    while chars > 1:
        chars -= 1
        bits -= 6
        out += bytes([ITOA64[(src >> bits) & 0x3F]])
    return out


def enc_bytes(data):
    """yescrypt-common.c encode64: little-endian groups of up to 3 bytes."""
    out = b""
    for i in range(0, len(data), 3):
        group = data[i:i + 3]
        value = int.from_bytes(group, "little")
        for _ in range((len(group) * 8 + 5) // 6):
            out += bytes([ITOA64[value & 0x3F]])
            value >>= 6
    return out


def setting(flavor, n_log2, r, p=1, t=0, salt=b"0123456789abcdef"):
    s = b"$y$" + enc_u32(flavor, 0) + enc_u32(n_log2, 1) + enc_u32(r, 1)
    have = (1 if p != 1 else 0) | (2 if t else 0)
    if have:
        s += enc_u32(have, 1)
        if have & 1:
            s += enc_u32(p, 2)
        if have & 2:
            s += enc_u32(t, 1)
    return s + b"$" + enc_bytes(salt)


def crypt(password, settings):
    out = lib.crypt(password, settings)
    assert out and not out.startswith(b"*"), (password, settings, out)
    return out


def main():
    rw = 2 + (0xB4 >> 2)  # YESCRYPT_RW with the default flavor bits: 'j'
    settings = [lib.crypt_gensalt(b"$y$", cost, hashlib.sha256(b"%d" % cost).digest(), 32)
                for cost in (1, 3, 5)]
    settings += [
        setting(rw, 10, 8),                       # 1 MiB
        setting(rw, 12, 32),                      # libxcrypt's default, 16 MiB, prehashed
        setting(rw, 11, 16, p=2),                 # two lanes
        setting(rw, 10, 8, t=1),
        setting(rw, 10, 8, t=3),
        setting(rw, 9, 1),                        # the smallest r pwxform allows
        setting(1, 10, 8),                        # WORM
        setting(1, 10, 8, t=2),                   # WORM with t
        setting(1, 10, 8, p=3, t=1),              # WORM: three lanes, t = 1
        setting(0, 10, 8),                        # classic scrypt in $y$ form
        setting(rw, 10, 8, salt=b""),             # an empty salt
        setting(rw, 10, 8, salt=bytes(range(64))),
    ]
    # "$7$": N_log2 as one character, r and p as 30-bit little-endian fields,
    # and the salt used as written.
    def seven(n_log2, r, p, salt):
        return b"$7$" + bytes([ITOA64[n_log2]]) + enc_bytes(r.to_bytes(4, "little"))[:5] \
            + enc_bytes(p.to_bytes(4, "little"))[:5] + salt
    settings.append(seven(10, 8, 1, b"SodiumChloride"))
    settings.append(seven(4, 1, 65, b"SodiumChloride"))  # p past one character

    cases = []
    passwords = [b"", b"pleaseletmein", "pässwörd".encode(), bytes(range(1, 200))]
    for i, s in enumerate(settings):
        pw = passwords[i % len(passwords)]
        h = crypt(pw, s)
        cases.append({"password": pw.hex(), "hash": h.hex(), "verifies": "true"})
        wrong = pw + b"x"
        assert crypt(wrong, h) != h
        cases.append({"password": wrong.hex(), "hash": h.hex(), "verifies": "false"})
    json.dump({
        "algorithm": "yescrypt ($y$) and scrypt ($7$) hashes, verification",
        "source": "scripts/gen_yescrypt_vectors.py with libxcrypt (Debian libcrypt1 "
                  "1:4.4.38-1) through ctypes, run on 2026-10-12. `password` and `hash` are "
                  "hex. Each hash is libxcrypt's crypt() of the password under a setting; "
                  "`verifies` says whether crypt() reproduces the hash for that password.",
        "cases": cases,
    }, sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
