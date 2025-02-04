import random
from des import CipherDES

class DiffieHellman:
    def __init__(self, p, g):
        # Inicializa os parâmetros do protocolo: um número primo p e uma base g
        self.p = p
        self.g = g

    # Gera uma chave privada aleatória dentro do intervalo [2, p-2]
    def generate_private_key(self):
        return random.randint(2, self.p - 2)

    # Gera a chave pública a partir da chave privada
    def generate_public_key(self, private_key):
        return pow(self.g, private_key, self.p)

    # Calcula o segredo compartilhado utilizando a chave privada do usuário e a chave pública do receptor
    def compute_shared_secret(self, private_key, public_key):
        return pow(public_key, private_key, self.p)

# Função principal que executa o processo de troca de chaves e criptografia
def main():
    # Definição dos parâmetros Diffie-Hellman
    p = 17  # Número primo
    g = 7   # Base

    # Instancia o objeto
    dh = DiffieHellman(p, g)

    # Gerar chaves do emissor
    private_key_sender = dh.generate_private_key()
    public_key_sender = dh.generate_public_key(private_key_sender)

    print("---Emissor---")
    print(f"Chave privada do emissor: {private_key_sender}")
    print(f"Chave pública do emissor: {public_key_sender}")

    # Enviar a chave pública do emissor ao receptor e receber a chave pública do receptor
    # O receptor fornece sua chave pública via input
    public_key_receiver = int(input("Digite a chave pública do receptor: "))

    # Calcular a chave compartilhada usando a chave privada do emissor e a chave pública do receptor
    shared_secret = dh.compute_shared_secret(private_key_sender, public_key_receiver)
    key = str(shared_secret)  # Usamos a chave compartilhada como chave do DES

    print(f"Chave compartilhada: {shared_secret}")

    # Criptografia com DES
    plaintext = input("Digite a mensagem para criptografar: ")
    des = CipherDES()
    ciphertext = des.encrypt(plaintext, key)

    print(f"Texto cifrado (hex): {ciphertext.hex()}")

    print("Envie este texto cifrado ao receptor.")

if __name__ == "__main__":
    main()
