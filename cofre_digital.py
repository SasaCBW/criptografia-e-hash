
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

ARQUIVO_CHAVE = Path("chave.key")


def carregar_chave():
    """Carrega a chave existente ou cria uma nova."""
    if ARQUIVO_CHAVE.exists():
        return ARQUIVO_CHAVE.read_bytes()

    chave = Fernet.generate_key()
    ARQUIVO_CHAVE.write_bytes(chave)
    return chave


def criptografar():
    mensagem = input("\nDigite a mensagem que deseja proteger: ")

    if not mensagem:
        print("A mensagem não pode estar vazia.")
        return

    chave = carregar_chave()
    cofre = Fernet(chave)

    mensagem_criptografada = cofre.encrypt(
        mensagem.encode("utf-8")
    )

    print("\nMensagem criptografada:")
    print(mensagem_criptografada.decode("utf-8"))


def descriptografar():
    mensagem = input(
        "\nCole a mensagem criptografada: "
    ).strip()

    if not mensagem:
        print("Digite uma mensagem criptografada.")
        return

    try:
        chave = carregar_chave()
        cofre = Fernet(chave)

        mensagem_original = cofre.decrypt(
            mensagem.encode("utf-8")
        )

        print("\nMensagem original:")
        print(mensagem_original.decode("utf-8"))

    except (InvalidToken, ValueError):
        print(
            "\nNão foi possível descriptografar. "
            "Verifique a mensagem e a chave."
        )


def gerar_hash():
    mensagem = input(
        "\nDigite o texto para gerar o hash: "
    )

    hash_sha256 = hashlib.sha256(
        mensagem.encode("utf-8")
    ).hexdigest()

    print("\nHash SHA-256:")
    print(hash_sha256)
    print("\nO hash não permite recuperar o texto original.")


def verificar_integridade():
    mensagem = input(
        "\nDigite o texto que deseja verificar: "
    )

    hash_informado = input(
        "Cole o hash original: "
    ).strip().lower()

    hash_calculado = hashlib.sha256(
        mensagem.encode("utf-8")
    ).hexdigest()

    if hash_calculado == hash_informado:
        print("\nResultado: o hash corresponde ao texto.")
    else:
        print(
            "\nResultado: o hash não corresponde. "
            "O texto pode ter sido alterado."
        )


def menu():
    while True:
        print("\n" + "=" * 42)
        print("       COFRE DIGITAL")
        print(" Proteção de Informações com Python")
        print("=" * 42)
        print("1 - Criptografar mensagem")
        print("2 - Descriptografar mensagem")
        print("3 - Gerar hash SHA-256")
        print("4 - Verificar integridade do texto")
        print("0 - Sair")

        opcao = input("\nEscolha uma opção: ").strip()

        if opcao == "1":
            criptografar()
        elif opcao == "2":
            descriptografar()
        elif opcao == "3":
            gerar_hash()
        elif opcao == "4":
            verificar_integridade()
        elif opcao == "0":
            print("\nCofre Digital encerrado. Até mais!")
            break
        else:
            print("\nOpção inválida. Tente novamente.")


if __name__ == "__main__":
    menu()
