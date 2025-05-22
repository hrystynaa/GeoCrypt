import click
import json
import zipfile
import logging
import tomllib
from pathlib import Path
import base64

# Імпортуємо наші модулі IO та Crypto
from io_module import read_and_validate
from crypto_module import (
    generate_x25519_keypair, export_key_to_files,
    import_private_key, import_public_key,
    derive_shared_key, aes_gcm_encrypt, aes_gcm_decrypt,
    encode_key_to_str, decode_key_from_str
)

# Налаштування логування: INFO або DEBUG (за допомогою --debug)
logger = logging.getLogger()
handler = logging.StreamHandler()
formatter = logging.Formatter("[%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)

def load_config(path):
    """
    Завантажує конфігурацію з TOML-файлу.
    """
    try:
        with open(path, "rb") as f:
            config = tomllib.load(f)
        return config
    except Exception as e:
        logger.error(f"Не вдалося зчитати конфігураційний файл: {e}")
        raise

@click.group()
@click.option('--config', default='config.toml', help="Шлях до TOML-файлу конфігурації", type=click.Path(exists=True))
@click.option('--debug', is_flag=True, help="Увімкнути режим відладки (DEBUG логування)")
@click.pass_context
def cli(ctx, config, debug):
    """
    Інтерфейс командного рядка для шифрування геопросторових даних.
    """
    if debug:
        logger.setLevel(logging.DEBUG)
    ctx.ensure_object(dict)
    ctx.obj['CONFIG'] = config

@cli.command()
@click.pass_context
def keygen(ctx):
    """
    Генерує пару ключів (X25519) і зберігає їх за шляхами з конфігурації.
    """
    config = load_config(ctx.obj['CONFIG'])
    priv_path = config.get("keys", {}).get("private")
    pub_path = config.get("keys", {}).get("public")
    if not priv_path or not pub_path:
        logger.error("У конфігурації не вказані шляхи до ключів")
        return
    try:
        priv, pub = generate_x25519_keypair()
        export_key_to_files(priv, pub, priv_path, pub_path)
        logger.info(f"Згенеровано ключі. Приватний ключ збережено у {priv_path}, публічний - у {pub_path}.")
    except Exception as e:
        logger.error(f"Не вдалося згенерувати ключі: {e}")

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', default=None, type=click.Path(), help="Шлях для вихідного ZIP-файлу")
@click.pass_context
def encrypt(ctx, input_file, output):
    """
    Зашифровує файл (GeoJSON, KML або CSV) в ZIP-архів із метаданими.
    """
    config = load_config(ctx.obj['CONFIG'])
    # Зчитуємо вхідні дані
    try:
        filename, data_bytes = read_and_validate(input_file, config)
    except Exception as e:
        logger.error(f"Помилка під час читання файлу: {e}")
        return

    # Імпортуємо публічний ключ отримувача
    pub_key_path = config.get("keys", {}).get("public")
    if not pub_key_path:
        logger.error("Не вказано публічний ключ отримувача у конфігурації")
        return
    try:
        receiver_pub = import_public_key(pub_key_path)
    except Exception as e:
        logger.error(e)
        return

    # Генеруємо ефемерну пару та спільний секрет
    eph_priv, eph_pub = generate_x25519_keypair()
    shared = derive_shared_key(eph_priv, receiver_pub)
    logger.debug("Обчислено спільний секрет для шифрування")

    # Шифруємо дані AES-GCM
    ciphertext, nonce, tag = aes_gcm_encrypt(data_bytes, shared)
    logger.info(f"Дані успішно зашифровано (AES-GCM).")

    # Підготовка ZIP
    zip_path = output if output else f"{Path(input_file).stem}_encrypted.zip"
    metadata = {
        "filename": filename,
        "ephemeral_key": encode_key_to_str(eph_pub),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }
    try:
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.writestr("encrypted_data.bin", ciphertext)
            zf.writestr("metadata.json", json.dumps(metadata))
        logger.info(f"Результат записано у архів: {zip_path}")
    except Exception as e:
        logger.error(f"Не вдалося створити ZIP-архів: {e}")

@cli.command()
@click.argument('zip_file', type=click.Path(exists=True))
@click.pass_context
def decrypt(ctx, zip_file):
    """
    Розшифровує ZIP-архів, створений командою encrypt.
    В результаті відновлює оригінальний файл.
    """
    config = load_config(ctx.obj['CONFIG'])
    priv_key_path = config.get("keys", {}).get("private")
    if not priv_key_path:
        logger.error("Не вказано приватний ключ отримувача у конфігурації")
        return
    try:
        own_priv = import_private_key(priv_key_path)
    except Exception as e:
        logger.error(e)
        return

    # Відкриваємо ZIP і зчитуємо дані
    try:
        with zipfile.ZipFile(zip_file, 'r') as zf:
            ciphertext = zf.read("encrypted_data.bin")
            metadata = json.loads(zf.read("metadata.json"))
    except Exception as e:
        logger.error(f"Не вдалося відкрити ZIP або зчитати файли: {e}")
        return

    # Декодуємо поля метаданих
    filename = metadata.get("filename")
    eph_key_b64 = metadata.get("ephemeral_key")
    nonce_b64 = metadata.get("nonce")
    tag_b64 = metadata.get("tag")
    if not filename or not eph_key_b64 or not nonce_b64 or not tag_b64:
        logger.error("Неповні метадані в архіві")
        return

    try:
        eph_pub = decode_key_from_str(eph_key_b64)
        nonce = base64.b64decode(nonce_b64)
        tag = base64.b64decode(tag_b64)
    except Exception as e:
        logger.error(f"Помилка обробки метаданих: {e}")
        return

    # Обчислюємо спільний секрет
    try:
        shared = derive_shared_key(own_priv, eph_pub)
    except Exception as e:
        logger.error(e)
        return

    # Розшифровуємо AES-GCM
    try:
        plaintext = aes_gcm_decrypt(ciphertext, nonce, tag, shared)
    except Exception as e:
        logger.error(f"Не вдалося розшифрувати дані: {e}")
        return

    # Записуємо відновлені дані у файл
    try:
        with open(filename, "wb") as f:
            f.write(plaintext)
        logger.info(f"Файл розшифровано і збережено як '{filename}'.")
    except Exception as e:
        logger.error(f"Не вдалося записати файл '{filename}': {e}")


if __name__ == "__main__":
    cli()   

