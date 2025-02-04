
INITIAL_PERMUTATION  = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FINAL_PERMUTATION  = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

EXPANSION_TABLE = [
    32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

PERMUTATION = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
]

# Tabelas e constantes necessárias para a implementação do DES
class CipherDES:
    INITIAL_PERM = INITIAL_PERMUTATION
    FINAL_PERM = FINAL_PERMUTATION
    S_BOXES = S_BOXES
    EXPANSION = EXPANSION_TABLE
    PC1_TABLE = PC1
    PC2_TABLE = PC2
    PERMUTATION = PERMUTATION
    SHIFT_COUNTS = SHIFTS

    def __init__(self):
        pass

    # Função para preparar a chave (garante que a chave seja de 8 bytes)
    def prepare_key(self, key):
        return (key.encode('utf-8')[:8]).ljust(8, b'\x00')  # Preenche com 0 caso necessário

    # Função para aplicar permutações usando uma tabela
    def apply_permutation(self, bit_list, table):
        result = []
        for i in table:
            result.append(bit_list[i - 1])  # Permuta os bits conforme a tabela
        return result

    # Função para aplicar a operação XOR bit a bit entre dois conjuntos de bits
    def bitwise_xor(self, bits1, bits2):
        result = []
        for b1, b2 in zip(bits1, bits2):
            result.append(b1 ^ b2) # Realiza a operação XOR entre os bits
        return result

    # Função para realizar uma rotação à esquerda nos bits
    def rotate_left(self, bit_list, n):
        length = len(bit_list)
        n = n % length  # Garante que n não ultrapasse o tamanho da lista
        rotated = [bit_list[(i + n) % length] for i in range(length)]
        return rotated

    # Função para gerar as chaves de rodada a partir da chave original
    def generate_round_keys(self, key_bits):
        key = self.apply_permutation(key_bits, self.PC1_TABLE) # Aplica permutação inicial (PC-1)
        C, D = key[:28], key[28:]  # Divide a chave em duas partes (C e D)
        round_keys = []

        # Para cada número de deslocamento, rotaciona C e D e gera a chave de rodada
        for shift in self.SHIFT_COUNTS:
            C, D = self.rotate_left(C, shift), self.rotate_left(D, shift)  # Rotaciona C e D
            round_keys.append(self.apply_permutation(C + D, self.PC2_TABLE))  # Aplica permutação final (PC-2)

        return round_keys

    # Função para adicionar padding ao dado (completa com 0's para múltiplos de 8 bytes)
    def pad_data(self, data):
        padding_size = 8 - len(data) % 8 # Calcula o tamanho do padding necessário
        encoded_data = data.encode('utf-8') # Codifica os dados para bytes
        encoded_data += bytes([padding_size] * padding_size) # Adiciona o padding
        return encoded_data

    # Função para remover o padding ao decifrar os dados
    def remove_padding(self, data):
        padding_size = data[-1] # O padding está no último byte
        result = data[:-padding_size] # Remove o padding
        return result.decode('utf-8') # Retorna os dados decodificados

    # Função para processar um bloco de dados usando as chaves de rodada
    def process_block(self, block_bits, round_keys):
        permuted_block = self.apply_permutation(block_bits, self.INITIAL_PERM) # Aplica permutação inicial (INITIAL_PERMUTATION)
        L, R = permuted_block[:32], permuted_block[32:] # Divide o bloco em L (esquerda) e R (direita)

        # Para cada chave de rodada, aplica a expansão, XOR, substituição e permutação
        for round_key in round_keys:
            expanded_R = self.apply_permutation(R, self.EXPANSION) # Expande a parte direita
            xored_R = self.bitwise_xor(expanded_R, round_key) # Aplica XOR com a chave de rodada

            # Realiza a substituição usando as S_Boxes
            substituted_bits = [
                int(bit) for i in range(8)
                for bit in
                f"{self.S_BOXES[i][(xored_R[i * 6] << 1) + xored_R[i * 6 + 5]][(xored_R[i * 6 + 1] << 3) + (xored_R[i * 6 + 2] << 2) + (xored_R[i * 6 + 3] << 1) + xored_R[i * 6 + 4]]:04b}"
            ]

            # Aplica permutação na parte substituída
            permuted_substituted = self.apply_permutation(substituted_bits, self.PERMUTATION)
            new_R = self.bitwise_xor(L, permuted_substituted) # Aplica XOR com a parte esquerda

            # Troca L e R
            L, R = R, new_R

        combined_block = R + L # Junta as partes finalizadas
        return self.apply_permutation(combined_block, self.FINAL_PERM) # Aplica permutação final (FINAL_PERMUTATION)

    # Função para decifrar um bloco de dados usando as chaves de rodada em ordem reversa
    def decrypt_block(self, block_bits, round_keys):
        reversed_round_keys = []
        for key in reversed(round_keys):  # Inverte a ordem das chaves de rodada
            reversed_round_keys.append(key)
        return self.process_block(block_bits, reversed_round_keys) # Processa o bloco com as chaves invertidas

    # Converte uma lista de bits para bytes
    def bits_to_bytes(self, bits):
        return bytes(int(''.join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))

    # Converte dados em bytes para uma lista de bits
    def bytes_to_bits(self, data):
        return [int(bit) for byte in data for bit in f"{byte:08b}"]

    # Função principal de criptografia
    def encrypt(self, plaintext, key):
        key_data = self.prepare_key(key) # Prepara a chave
        key_bits = self.bytes_to_bits(key_data) # Converte a chave para bits
        round_keys = self.generate_round_keys(key_bits) # Gera as chaves de rodada
        padded_message = self.pad_data(plaintext) # Adiciona padding aos dados
        encrypted_data = b''

        # Criptografa os dados em blocos de 8 bytes
        for i in range(0, len(padded_message), 8):
            block = padded_message[i:i + 8]
            block_bits = self.bytes_to_bits(block)
            encrypted_bits = self.process_block(block_bits, round_keys) # Criptografa o bloco
            encrypted_data += self.bits_to_bytes(encrypted_bits) # Converte os bits criptografados para bytes

        return encrypted_data

    # Função principal de descriptografia
    def decrypt(self, ciphertext, key):
        key_data = self.prepare_key(key) # Prepara a chave
        key_bits = self.bytes_to_bits(key_data) # Converte a chave para bits
        round_keys = self.generate_round_keys(key_bits) # Gera as chaves de rodada

        decrypted_message = b''

        # Descriptografa os dados em blocos de 8 bytes
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i + 8]
            block_bits = self.bytes_to_bits(block)
            decrypted_bits = self.decrypt_block(block_bits, round_keys) # Descriptografa o bloco
            decrypted_message += self.bits_to_bytes(decrypted_bits) # Converte os bits descriptografados para bytes

        return self.remove_padding(decrypted_message) # Remove o padding e retorna os dados "filtrados"

    # Função para exibir os resultados da criptografia
    def encryption_result(self, key, plaintext):
        encrypted_data = self.encrypt(plaintext, key) # Criptografa o texto
        print(f"Original text: {plaintext}")
        print()
        print(f"Encrypted text (hex): {encrypted_data.hex()}")
        print()
        decrypted_text = self.decrypt(encrypted_data, key) # Descriptografa o texto
        print(f"Decrypted text: {decrypted_text}")

# Teste de funcionamento do DES
if __name__ == "__main__":
    message = "Mensagem Muito Secreta" # Mensagem exemplo
    key = "27" # Chave exemplo para teste
    des_cipher = CipherDES() # Instancia o objeto CipherDES
    des_cipher.encryption_result(key=key, plaintext=message) # Exibe os resultados da criptografia

