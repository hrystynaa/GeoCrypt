import click
import json
import zipfile
import tomllib
from pathlib import Path
import base64

from io_module import read_and_validate
from crypto_module import (
    generate_x25519_keypair, export_key_to_files,
    import_private_key, import_public_key,
    derive_shared_key, aes_gcm_encrypt, aes_gcm_decrypt,
    encode_key_to_str, decode_key_from_str
)

def load_config(path):
    with open(path, "rb") as f:
        config = tomllib.load(f)
    return config

@click.group()
@click.option('--config', default='config.toml', help="Path to config TOML file", type=click.Path(exists=True))
@click.option('--debug', is_flag=True, help="Enable debug logging")
@click.pass_context
def cli(ctx, config, debug):
    ctx.ensure_object(dict)
    ctx.obj['CONFIG'] = config

@cli.command()
@click.pass_context
def keygen(ctx):
    config = load_config(ctx.obj['CONFIG'])
    priv_path = config.get("keys", {}).get("private")
    pub_path = config.get("keys", {}).get("public")
    priv, pub = generate_x25519_keypair()
    export_key_to_files(priv, pub, priv_path, pub_path)
    print(f"Keys generated. Private: {priv_path}, Public: {pub_path}")

@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--output', default=None, type=click.Path(), help="Output ZIP file path")
@click.pass_context
def encrypt(ctx, input_file, output):
    config = load_config(ctx.obj['CONFIG'])
    filename, data_bytes = read_and_validate(input_file, config)
    pub_key_path = config.get("keys", {}).get("public")
    receiver_pub = import_public_key(pub_key_path)
    eph_priv, eph_pub = generate_x25519_keypair()
    shared = derive_shared_key(eph_priv, receiver_pub)
    ciphertext, nonce, tag = aes_gcm_encrypt(data_bytes, shared)
    zip_path = output if output else f"{Path(input_file).stem}_encrypted.zip"
    metadata = {
        "filename": filename,
        "ephemeral_key": encode_key_to_str(eph_pub),
        "nonce": base64.b64encode(nonce).decode('utf-8'),
        "tag": base64.b64encode(tag).decode('utf-8')
    }
    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.writestr("encrypted_data.bin", ciphertext)
        zf.writestr("metadata.json", json.dumps(metadata))
    print(f"Encrypted archive written: {zip_path}")

@cli.command()
@click.argument('zip_file', type=click.Path(exists=True))
@click.pass_context
def decrypt(ctx, zip_file):
    config = load_config(ctx.obj['CONFIG'])
    priv_key_path = config.get("keys", {}).get("private")
    own_priv = import_private_key(priv_key_path)
    with zipfile.ZipFile(zip_file, 'r') as zf:
        ciphertext = zf.read("encrypted_data.bin")
        metadata = json.loads(zf.read("metadata.json"))
    filename = metadata["filename"]
    eph_pub = decode_key_from_str(metadata["ephemeral_key"])
    nonce = base64.b64decode(metadata["nonce"])
    tag = base64.b64decode(metadata["tag"])
    shared = derive_shared_key(own_priv, eph_pub)
    plaintext = aes_gcm_decrypt(ciphertext, nonce, tag, shared)
    with open(filename, "wb") as f:
        f.write(plaintext)
    print(f"Decrypted file written: {filename}")

if __name__ == "__main__":
    cli()
