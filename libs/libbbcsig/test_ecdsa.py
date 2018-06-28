import binascii
import os
from ctypes import *

CURVETYPE_SECP256 = 1
CURVETYPE_P256 = 2

if os.name == "nt":
    lib = windll.LoadLibrary("libbbcsig.dll")
else:
    lib = cdll.LoadLibrary("libbbcsig.so")

test_digest = binascii.a2b_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
privkey_len = c_int32(32)
privkey     = (c_byte * privkey_len.value)()
pubkey_len  = c_int32(65)
pubkey      = (c_byte * pubkey_len.value)()

signature = (c_byte * 64)()

print("# -- generate_keypair()")
lib.generate_keypair(CURVETYPE_SECP256, 0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- sign()")
sig_r = (c_byte * 32)()
sig_s = (c_byte * 32)()
sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
sig_s_len = (c_byte * 4)()
print(lib.sign(CURVETYPE_SECP256, privkey_len, privkey, privkey_len, test_digest, sig_r, sig_s, sig_r_len, sig_s_len))
sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
sig_r = binascii.a2b_hex("00" * (32 - sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
sig_s = binascii.a2b_hex("00" * (32 - sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
signature = bytes(bytearray(sig_r)+bytearray(sig_s))
print(binascii.b2a_hex(signature))

print("# -- output_der()")
der_data = (c_byte * 512)()     # 256 -> 512
der_len = lib.output_der(CURVETYPE_SECP256, privkey_len, privkey, byref(der_data))
print("DER: len=", der_len, "  dat=", binascii.b2a_hex(bytearray(der_data)[:der_len]))

print("# -- clear private key")
privkey = (c_byte * privkey_len.value)()
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)

print("# -- convert_from_der()")
lib.convert_from_der(CURVETYPE_SECP256, der_len, byref(der_data), 0, byref(pubkey_len), pubkey, byref(privkey_len), privkey)
print("private_key:", binascii.b2a_hex(privkey), ", len=", privkey_len)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- sign()")
sig_r = (c_byte * 32)()
sig_s = (c_byte * 32)()
sig_r_len = (c_byte * 4)()  # Adjust size according to the expected size of sig_r and sig_s. Default:uint32.
sig_s_len = (c_byte * 4)()
print(lib.sign(CURVETYPE_SECP256, privkey_len, privkey, privkey_len, test_digest, sig_r, sig_s, sig_r_len, sig_s_len))
sig_r_len = int.from_bytes(bytes(sig_r_len), "little")
sig_s_len = int.from_bytes(bytes(sig_s_len), "little")
sig_r = binascii.a2b_hex("00" * (32 - sig_r_len) + bytes(sig_r)[:sig_r_len].hex())
sig_s = binascii.a2b_hex("00" * (32 - sig_s_len) + bytes(sig_s)[:sig_s_len].hex())
signature = bytes(bytearray(sig_r)+bytearray(sig_s))
print(binascii.b2a_hex(signature))

print("# -- get compressed pubkey")
pubkey = (c_byte * 33)()
lib.get_public_key_compressed(CURVETYPE_SECP256, privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- verify with compressed pubkey")
res = lib.verify(CURVETYPE_SECP256, pubkey_len, pubkey, 32, test_digest, 64, signature)
print("result:", res)

print("# -- get uncompressed pubkey")
pubkey = (c_byte * 65)()
lib.get_public_key_uncompressed(CURVETYPE_SECP256, privkey_len, privkey, byref(pubkey_len), pubkey)
print("public_key:", binascii.b2a_hex(pubkey), ", len=", pubkey_len)

print("# -- verify with compressed pubkey")
res = lib.verify(CURVETYPE_SECP256, pubkey_len, pubkey, 32, test_digest, 64, signature)
print("result:", res)

print("# -- output_pem()")
pem = (c_char * 512)()      # 256 -> 512
length = lib.output_pem(CURVETYPE_SECP256, privkey_len, privkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)

print("# -- output_publickey_pem()")
pem = (c_char * 512)()      # 256 -> 512
print(bytes(pubkey).hex())
print(pubkey_len)
length = lib.output_public_key_pem(CURVETYPE_SECP256, pubkey_len, pubkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)
length = lib.output_public_key_der(CURVETYPE_SECP256, pubkey_len, pubkey, byref(pem))
print("DER: len=", length, " dat=", pem.value)
length = lib.output_pem(CURVETYPE_SECP256, privkey_len, privkey, byref(pem))
print("PEM: len=", length, " dat=", pem.value)
length = lib.output_der(CURVETYPE_SECP256, privkey_len, privkey, byref(pem))
print("DER: len=", length, " dat=", pem.value)
