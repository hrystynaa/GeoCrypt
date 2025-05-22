from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_keypair():
    private_key = ECC.generate(curve='curve25519')
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_data(data: bytes, recipient_pubkey: ECC.EccKey) -> dict:
    ephemeral_private, ephemeral_public = generate_keypair()
    shared_secret = ephemeral_private.d * recipient_pubkey.pointQ
    aes_key = int.to_bytes(shared_secret.x, 32, 'big')
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'ciphertext': ciphertext,
        'nonce': nonce,
        'tag': tag,
        'ephemeral_pubkey': ephemeral_public.export_key(format='DER')
    }