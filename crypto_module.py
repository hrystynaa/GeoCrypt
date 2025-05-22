from pathlib import Path
from Crypto.PublicKey import ECC
from Crypto.Protocol import DH
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

def generate_x25519_keypair():
    """
    Генерує пару X25519 ключів та повертає (private_key, public_key) у вигляді EccKey.
    """
    key = ECC.generate(curve='curve25519')
    priv = key
    pub = key.public_key()
    return priv, pub

def export_key_to_files(private_key, public_key, priv_path, pub_path):
    """
    Зберігає приватний і публічний ключі у PEM-файли.
    """
    try:
        # Додаємо створення папки, якщо її немає
        Path(priv_path).parent.mkdir(parents=True, exist_ok=True)
        Path(pub_path).parent.mkdir(parents=True, exist_ok=True)
        
        priv_pem = private_key.export_key(format='PEM', use_pkcs8=True)
        pub_pem = public_key.export_key(format='PEM')
        with open(priv_path, 'wt') as f:
            f.write(priv_pem)
        with open(pub_path, 'wt') as f:
            f.write(pub_pem)
    except Exception as e:
        raise IOError(f"Помилка запису ключів: {e}")

def import_private_key(path):
    """
    Імпортує приватний ключ із PEM-файлу.
    """
    try:
        with open(path, 'rt') as f:
            data = f.read()
        key = ECC.import_key(data)
        return key
    except Exception as e:
        raise IOError(f"Не вдалося імпортувати приватний ключ: {e}")

def import_public_key(path):
    """
    Імпортує публічний ключ із PEM-файлу.
    """
    try:
        with open(path, 'rt') as f:
            data = f.read()
        key = ECC.import_key(data)
        return key
    except Exception as e:
        raise IOError(f"Не вдалося імпортувати публічний ключ: {e}")

def derive_shared_key(our_priv, their_pub):
    """
    Обчислює спільний секрет на базі нашого приватного і їхнього публічного ключів (X25519).
    Використовується SHA-256 як KDF для отримання 32-байтового ключа AES.
    """
    def sha256_kdf(x):
        return SHA256.new(x).digest()
    try:
        shared = DH.key_agreement(
            static_priv=our_priv,
            eph_pub=their_pub,
            kdf=sha256_kdf
        )
        return shared
    except Exception as e:
        raise ValueError(f"Не вдалося виконати обмін ключами: {e}")

def aes_gcm_encrypt(data, key):
    """
    Шифрує дані (байти) за допомогою AES-GCM. Генерує випадковий 12-байтовий nonce.
    Повертає (ciphertext, nonce, tag).
    """
    nonce = get_random_bytes(12)  # 12 байт рекомендовано для GCM
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, nonce, tag

def aes_gcm_decrypt(ciphertext, nonce, tag, key):
    """
    Розшифровує дані AES-GCM з перевіркою тегу. Повертає початкові байти.
    У разі невідповідності тегу викидає ValueError.
    """
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        raise ValueError("Не вдалося пройти перевірку тегу: дані пошкоджені або ключ невірний")

def encode_key_to_str(pub_key):
    """
    Приймає публічний EccKey (X25519) і повертає строку з base64- кодуванням його RAW-ключа (32 байти).
    Це потрібно для зберігання ефемерного ключа у метаданих.
    """
    raw = pub_key.export_key(format='raw')
    return base64.b64encode(raw).decode('utf-8')

def decode_key_from_str(b64_str):
    """
    Декодує base64-рядок у 32-байтовий публічний X25519 ключ (EccKey).
    """
    raw = base64.b64decode(b64_str)
    try:
        key = DH.import_x25519_public_key(raw)
        return key
    except ValueError as e:
        raise ValueError(f"Помилка імпорту ефемерного публічного ключа: {e}")

