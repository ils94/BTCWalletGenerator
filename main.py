import hashlib
import bip32utils
from mnemonic import Mnemonic


# Helper functions for Bech32 encoding
def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= generator[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def generate_segwit_address(public_key):
    # SHA-256 hashing on the public key
    sha256 = hashlib.sha256(public_key).digest()

    # RIPEMD-160 hashing on the result of SHA-256
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256)
    hashed_public_key = ripemd160.digest()

    # Native SegWit address generation (BIP-84)
    # Define the witness version and the hash
    witness_version = 0
    witness_program = convertbits(hashed_public_key, 8, 5)

    # Build the SegWit address
    address = bech32_encode('bc', [witness_version] + witness_program)

    return address


# Create a new Mnemonic instance with the 'english' word list
mnemo = Mnemonic("english")

# Generate a 24-word mnemonic phrase
mnemonic_phrase = mnemo.generate(strength=256)
print(f"Mnemonic Phrase: {mnemonic_phrase}")
print("")

# Generate seed from the mnemonic phrase
seed = mnemo.to_seed(mnemonic_phrase)

# Generate a BIP32 root key from the seed
root_key = bip32utils.BIP32Key.fromEntropy(seed)

# Generate the first 5 addresses using the BIP-84 derivation path
addresses = []
for i in range(20):
    child_key = root_key.ChildKey(84 + bip32utils.BIP32_HARDEN) \
        .ChildKey(0 + bip32utils.BIP32_HARDEN) \
        .ChildKey(0 + bip32utils.BIP32_HARDEN) \
        .ChildKey(0) \
        .ChildKey(i)
    # Get the public key from the child key (compressed format)
    public_key = child_key.PublicKey()
    address = generate_segwit_address(public_key)
    addresses.append(address)

for i, address in enumerate(addresses):
    print(f"Address {i + 1}: {address}")
