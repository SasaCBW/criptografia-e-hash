import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ARQUIVO_CHAVE = Path("chave.key")


def carregar_chave():
    """Cria uma chave ou carrega a chave já existente."""
    if ARQUIVO_CHAVE.exists():
        return ARQUIVO_CHAVE.read_bytes()

    chave = Fernet.generate_key()
    ARQUIVO_CHAVE.write_bytes(chave)
    try:
        os.chmod(ARQUIVO_CHAVE, 0o600)
    except OSError:
        pass

    return chave


def criptografar():
    mensagem = input("Digite a mensagem: ")

    if not mensagem:
        print("A mensagem não pode estar vazia.")
        return

    senha = input("Crie uma senha com pelo menos 8 caracteres: ")

    if len(senha) < 8:
        print("A senha precisa ter pelo menos 8 caracteres.")
        return

    salt = os.urandom(16)
    chave_base = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        salt,
        310000,
        dklen=32,
    )

    chave = base64.urlsafe_b64encode(chave_base)
    cofre = Fernet(chave)
    conteudo = cofre.encrypt(mensagem.encode("utf-8"))

    pacote = {
        "version": 1,
        "algorithm": "Fernet",
        "kdf": "PBKDF2-SHA256",
        "iterations": 310000,
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": conteudo.decode("ascii"),
    }

    print("\nMensagem protegida:")
    print(json.dumps(pacote, ensure_ascii=False))


def descriptografar():
    texto = input("Cole o pacote criptografado: ")
    senha = input("Digite a senha original: ")

    try:
        pacote = json.loads(texto)

        if (
            pacote.get("version") != 1
            or pacote.get("algorithm") != "Fernet"
            or pacote.get("kdf") != "PBKDF2-SHA256"
            or pacote.get("iterations") != 310000
        ):
            raise ValueError("Formato não reconhecido.")

        salt = base64.b64decode(pacote["salt"], validate=True)

        if len(salt) != 16:
            raise ValueError("Salt inválido.")

        chave_base = hashlib.pbkdf2_hmac(
            "sha256",
            senha.encode("utf-8"),
            salt,
            310000,
            dklen=32,
        )

        chave = base64.urlsafe_b64encode(chave_base)
        cofre = Fernet(chave)

        original = cofre.decrypt(
            pacote["data"].encode("ascii")
        )

        print("\nMensagem original:")
        print(original.decode("utf-8"))

    except (
        InvalidToken,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        UnicodeDecodeError,
    ):
        print("Não foi possível descriptografar.")
        print("Confira o pacote e a senha.")


def gerar_hash():
    texto = input("Digite o texto: ")
    resultado = hashlib.sha256(
        texto.encode("utf-8")
    ).hexdigest()

    print("\nHash SHA-256:")
    print(resultado)


def verificar_hash():
    texto = input("Digite o texto que deseja verificar: ")
    esperado = input("Cole o hash original: ").strip().lower()

    if len(esperado) != 64 or any(
        caractere not in "0123456789abcdef"
        for caractere in esperado
    ):
        print("O hash informado não tem formato SHA-256 válido.")
        return

    calculado = hashlib.sha256(
        texto.encode("utf-8")
    ).hexdigest()

    if hashlib.compare_digest(calculado, esperado):
        print("Os hashes correspondem.")
    else:
        print("Os hashes são diferentes.")


def menu():
    while True:
        print("\n" + "=" * 44)
        print("           COFRE DIGITAL")
        print(" Proteção de Informações com Python")
        print("=" * 44)
        print("1 - Criptografar mensagem")
        print("2 - Descriptografar mensagem")
        print("3 - Gerar hash SHA-256")
        print("4 - Verificar integridade")
        print("0 - Sair")

        opcao = input("\nEscolha uma opção: ").strip()

        if opcao == "1":
            criptografar()
        elif opcao == "2":
            descriptografar()
        elif opcao == "3":
            gerar_hash()
        elif opcao == "4":
            verificar_hash()
        elif opcao == "0":
            print("Programa encerrado.")
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    menu()
