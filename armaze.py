# Armazenamento dos arquivos criptografados - complemento do Cofre de Arquivos

import os
import shutil

PASTA_COFRE = "cofre_armazenado"


# Salvar arquivo .cofre (e a assinatura, se existir)

def salvar_no_cofre(nome_cofre):

    if not os.path.exists(nome_cofre):
        print("Arquivo não encontrado.")
        return False

    if not nome_cofre.endswith(".cofre"):
        print("Informe um arquivo .cofre.")
        return False

    os.makedirs(PASTA_COFRE, exist_ok=True)

    shutil.copy(nome_cofre, PASTA_COFRE)

    # Copia também a assinatura, caso exista
    if os.path.exists(nome_cofre + ".sig"):
        shutil.copy(nome_cofre + ".sig", PASTA_COFRE)

    print("Arquivo guardado em:", PASTA_COFRE)
    return True


# Listar arquivos guardados

def listar_cofre():

    if not os.path.exists(PASTA_COFRE) or not os.listdir(PASTA_COFRE):
        print("O cofre está vazio.")
        return

    print("\n--- Arquivos guardados ---")

    for nome in os.listdir(PASTA_COFRE):
        print("-", nome)


# Recuperar arquivo guardado

def recuperar_do_cofre(nome_cofre):

    origem = os.path.join(PASTA_COFRE, nome_cofre)

    if not os.path.exists(origem):
        print("Arquivo não encontrado no cofre.")
        return False

    if os.path.exists(nome_cofre):
        print("Já existe um arquivo com esse nome na pasta atual.")
        return False

    shutil.copy(origem, ".")

    print("Arquivo recuperado:", nome_cofre)
    return True


# Menu

def menu_armazenamento():

    while True:

        print("\n--- Armazenamento do Cofre ---")
        print("1 - Guardar arquivo .cofre")
        print("2 - Listar arquivos guardados")
        print("3 - Recuperar arquivo")
        print("0 - Voltar")

        opcao = input("Escolha uma opção: ")

        if opcao == "1":
            salvar_no_cofre(input("Nome do arquivo .cofre: "))

        elif opcao == "2":
            listar_cofre()

        elif opcao == "3":
            recuperar_do_cofre(input("Nome do arquivo .cofre: "))

        elif opcao == "0":
            break

        else:
            print("Opção inválida.")


if __name__ == "__main__":
    menu_armazenamento()