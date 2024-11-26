from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64

# Función para guardar datos en un archivo
def save_to_file(filename, data, binary=False):
    mode = 'wb' if binary else 'w'
    with open(filename, mode) as file:
        file.write(data)

# Función para leer datos de un archivo
def read_from_file(filename, binary=False):
    mode = 'rb' if binary else 'r'
    with open(filename, mode) as file:
        return file.read()

# Generar un par de claves (pública y privada)
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serializar la clave pública y privada
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guardar las claves en archivos
    save_to_file("private_key.pem", private_pem, binary=True)
    save_to_file("public_key.pem", public_pem, binary=True)

    print("Claves generadas y guardadas en archivos.")
    return private_key, public_key

# Firmar un mensaje
def sign_message(private_key, message):
    message_bytes = message.encode('utf-8')
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    save_to_file("signature.sig", signature, binary=True)
    print("Mensaje firmado y guardado en archivo.")
    return signature

# Verificar la firma
def verify_signature(public_key, message, signature):
    message_bytes = message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("La firma es válida.")
    except InvalidSignature:
        print("La firma es inválida.")

# Función principal
def main():
    try:
        # Generar claves y guardarlas en archivos
        private_key, public_key = generate_keys()

        # Mensaje a firmar
        message = "Hola, mundo!"

        # Firmar el mensaje
        signature = sign_message(private_key, message)

        # Verificar la firma
        verify_signature(public_key, message, signature)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
