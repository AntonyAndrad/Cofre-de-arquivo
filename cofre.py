# Cofre de arquivos e Autenticação de Mensagens - Entrega 1

import os
import shutil
import hmac
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature, InvalidTag

# Módulo de armazenamento dos arquivos criptografados
import armazenamento_cofre


# Configuração da criptografia RSA
OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


# Autenticação de mensagens com HMAC

class Usuario:

    def __init__(self, nome, chave=None):
        self.nome = nome
        self.chave = chave

    def _calcular_tag(self, mensagem):
        return hmac.new(
            self.chave.encode(),
            mensagem.encode(),
            digestmod="sha256"
        ).hexdigest()

    def enviar_mensagem(self, mensagem):
        if self.chave is None:
            print(f"{self.nome} não possui chave secreta.")
            return None

        tag = self._calcular_tag(mensagem)

        return {
            "mensagem": mensagem,
            "tag": tag
        }

    def verificar_mensagem(self, pacote):
        if self.chave is None or pacote is None:
            print(f"{self.nome} não possui chave para verificar a mensagem.")
            return False

        tag_calculada = self._calcular_tag(pacote["mensagem"])

        if hmac.compare_digest(tag_calculada, pacote["tag"]):
            print(f"{self.nome}: mensagem autêntica.")
            return True

        print(f"{self.nome}: mensagem adulterada ou inválida.")
        return False

    def alterar_mensagem(self, pacote):
        if pacote is None:
            return None

        pacote["mensagem"] += " (mensagem alterada)"
        return pacote


# Verificação das chaves

def validar_chaves():

    if not os.path.exists("chave_privada.pem"):
        print("Chave privada não encontrada.")
        return False

    if not os.path.exists("chave_publica.pem"):
        print("Chave pública não encontrada.")
        return False

    try:
        with open("chave_privada.pem", "rb") as arquivo:
            chave_privada = serialization.load_pem_private_key(
                arquivo.read(),
                password=None
            )

        with open("chave_publica.pem", "rb") as arquivo:
            chave_publica = serialization.load_pem_public_key(
                arquivo.read()
            )

        publica_da_privada = chave_privada.public_key()

        chave1 = publica_da_privada.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        chave2 = chave_publica.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if chave1 != chave2:
            print("As chaves não correspondem.")
            return False

        return True

    except Exception as erro:
        print("Erro ao validar as chaves:", erro)
        return False


# Gerar par de chaves

# Gerar par de chaves RSA e mostrar as chaves
def gerar_chaves():

    # Cria a chave privada RSA
    chave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Gera a chave pública a partir da privada
    chave_publica = chave_privada.public_key()

    # Salva a chave privada no arquivo PEM
    privada_pem = chave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    with open("chave_privada.pem", "wb") as arquivo:
        arquivo.write(privada_pem)

    # Salva a chave pública no arquivo PEM
    publica_pem = chave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("chave_publica.pem", "wb") as arquivo:
        arquivo.write(publica_pem)

    # Remove certificado antigo
    if os.path.exists("certificado.pem"):
        os.remove("certificado.pem")

    # Mostra as chaves no terminal
    print("\nPAR DE CHAVES GERADO COM SUCESSO!")

    print("\n===== CHAVE PRIVADA =====")
    print(privada_pem.decode())

    print("\n===== CHAVE PÚBLICA =====")
    print(publica_pem.decode())

    print("Atenção: guarde a chave privada em segurança!")

# Criar um arquivo de texto
def criar_arquivo():

    # Solicita o nome do arquivo
    nome = input("Digite o nome do arquivo: ")

    # Adiciona a extensão .txt
    if not nome.endswith(".txt"):
        nome += ".txt"

    # Solicita o conteúdo
    conteudo = input("Digite o conteúdo do arquivo: ")

    # Cria e escreve no arquivo
    with open(nome, "w", encoding="utf-8") as arquivo:
        arquivo.write(conteudo)

    print("Arquivo criado com sucesso:", nome)

# Criptografar arquivo

def criptografar(nome_arquivo):

    if not validar_chaves():
        return False

    with open(nome_arquivo, "rb") as arquivo:
        dados = arquivo.read()

    chave_aes = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    aes = AESGCM(chave_aes)
    dados_criptografados = aes.encrypt(nonce, dados, None)

    with open("chave_publica.pem", "rb") as arquivo:
        chave_publica = serialization.load_pem_public_key(
            arquivo.read()
        )

    chave_aes_criptografada = chave_publica.encrypt(
        chave_aes,
        OAEP
    )

    nome_saida = nome_arquivo + ".cofre"

    with open(nome_saida, "wb") as arquivo:
        arquivo.write(chave_aes_criptografada)
        arquivo.write(nonce)
        arquivo.write(dados_criptografados)

    print("Arquivo criptografado com sucesso:", nome_saida)
    return True


# Descriptografar arquivo

def descriptografar(nome_arquivo):

    if not validar_chaves():
        return False

    with open(nome_arquivo, "rb") as arquivo:
        dados = arquivo.read()

    if len(dados) < 284:
        print("Arquivo criptografado inválido ou incompleto.")
        return False

    chave_aes_criptografada = dados[:256]
    nonce = dados[256:268]
    dados_criptografados = dados[268:]

    with open("chave_privada.pem", "rb") as arquivo:
        chave_privada = serialization.load_pem_private_key(
            arquivo.read(),
            password=None
        )

    chave_aes = chave_privada.decrypt(
        chave_aes_criptografada,
        OAEP
    )

    aes = AESGCM(chave_aes)
    dados_originais = aes.decrypt(
        nonce,
        dados_criptografados,
        None
    )

    if nome_arquivo.endswith(".cofre"):
        nome_saida = nome_arquivo[:-6] + ".decifrado"
    else:
        nome_saida = nome_arquivo + ".decifrado"

    with open(nome_saida, "wb") as arquivo:
        arquivo.write(dados_originais)

    print("Arquivo descriptografado com sucesso:", nome_saida)
    return True


# Assinar arquivo digitalmente

def assinar_arquivo(nome_arquivo):

    if not validar_chaves():
        return False

    with open(nome_arquivo, "rb") as arquivo:
        dados = arquivo.read()

    with open("chave_privada.pem", "rb") as arquivo:
        chave_privada = serialization.load_pem_private_key(
            arquivo.read(),
            password=None
        )

    assinatura = chave_privada.sign(
        dados,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    with open(nome_arquivo + ".sig", "wb") as arquivo:
        arquivo.write(assinatura)

    print("Arquivo assinado digitalmente.")
    return True


# Verificar assinatura digital

def verificar_assinatura(nome_arquivo):

    if not validar_chaves():
        return False

    nome_assinatura = nome_arquivo + ".sig"

    if not os.path.exists(nome_assinatura):
        print("Assinatura não encontrada.")
        return False

    with open(nome_arquivo, "rb") as arquivo:
        dados = arquivo.read()

    with open(nome_assinatura, "rb") as arquivo:
        assinatura = arquivo.read()

    with open("chave_publica.pem", "rb") as arquivo:
        chave_publica = serialization.load_pem_public_key(
            arquivo.read()
        )

    try:
        chave_publica.verify(
            assinatura,
            dados,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("Assinatura válida. Arquivo íntegro.")
        return True

    except InvalidSignature:
        print("Assinatura inválida. O arquivo pode ter sido adulterado.")
        return False


# Testar adulteração de arquivo

def testar_adulteracao(nome_arquivo):

    if not os.path.exists(nome_arquivo):
        print("Arquivo não encontrado.")
        return False

    if not assinar_arquivo(nome_arquivo):
        return False

    nome_adulterado = "teste_adulterado.txt"

    shutil.copyfile(nome_arquivo, nome_adulterado)
    shutil.copyfile(
        nome_arquivo + ".sig",
        nome_adulterado + ".sig"
    )

    with open(nome_adulterado, "rb") as arquivo:
        dados = bytearray(arquivo.read())

    if len(dados) == 0:
        print("Não é possível adulterar um arquivo vazio.")
        return False

    dados[-1] ^= 1

    with open(nome_adulterado, "wb") as arquivo:
        arquivo.write(dados)

    resultado = verificar_assinatura(nome_adulterado)

    if not resultado:
        print("Teste de adulteração concluído: alteração detectada.")
        return True

    print("Falha no teste: alteração não detectada.")
    return False


# Gerenciar certificados

def gerar_certificado():

    if not validar_chaves():
        return False

    with open("chave_privada.pem", "rb") as arquivo:
        chave_privada = serialization.load_pem_private_key(
            arquivo.read(),
            password=None
        )

    nome = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Sergipe"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Aracaju"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cofre de Arquivos"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Usuario")
    ])

    agora = datetime.datetime.now(datetime.timezone.utc).replace(
        tzinfo=None
    )

    certificado = (
        x509.CertificateBuilder()
        .subject_name(nome)
        .issuer_name(nome)
        .public_key(chave_privada.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + datetime.timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .sign(chave_privada, hashes.SHA256())
    )

    with open("certificado.pem", "wb") as arquivo:
        arquivo.write(
            certificado.public_bytes(
                serialization.Encoding.PEM
            )
        )

    print("Certificado digital gerado com sucesso.")
    return True


def consultar_certificado():

    if not os.path.exists("certificado.pem"):
        print("Certificado não encontrado.")
        return

    with open("certificado.pem", "rb") as arquivo:
        certificado = x509.load_pem_x509_certificate(
            arquivo.read()
        )

    print("\nInformações do certificado:")
    print("Emissor:", certificado.issuer)
    print("Titular:", certificado.subject)
    print("Número de série:", certificado.serial_number)
    print("Válido a partir de:", certificado.not_valid_before)
    print("Válido até:", certificado.not_valid_after)


def validar_certificado():

    if not os.path.exists("certificado.pem"):
        print("Certificado não encontrado.")
        return False

    if not validar_chaves():
        return False

    try:
        with open("certificado.pem", "rb") as arquivo:
            certificado = x509.load_pem_x509_certificate(
                arquivo.read()
            )

        agora = datetime.datetime.now(datetime.timezone.utc).replace(
            tzinfo=None
        )

        if agora < certificado.not_valid_before:
            print("Certificado ainda não está válido.")
            return False

        if agora > certificado.not_valid_after:
            print("Certificado expirado.")
            return False

        with open("chave_publica.pem", "rb") as arquivo:
            chave_publica = serialization.load_pem_public_key(
                arquivo.read()
            )

        chave_certificado = certificado.public_key()

        publica1 = chave_publica.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        publica2 = chave_certificado.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        if publica1 != publica2:
            print("A chave do certificado não corresponde.")
            return False

        chave_certificado.verify(
            certificado.signature,
            certificado.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificado.signature_hash_algorithm
        )

        print("Certificado válido.")
        return True

    except Exception as erro:
        print("Erro ao validar certificado:", erro)
        return False


def gerenciar_certificados():

    while True:

        print("\n--- Gerenciar Certificados ---")
        print("1 - Gerar certificado")
        print("2 - Consultar certificado")
        print("3 - Validar certificado")
        print("0 - Voltar")

        opcao = input("Escolha uma opção: ")

        try:
            if opcao == "1":
                gerar_certificado()

            elif opcao == "2":
                consultar_certificado()

            elif opcao == "3":
                validar_certificado()

            elif opcao == "0":
                break

            else:
                print("Opção inválida.")

        except Exception as erro:
            print("Erro:", erro)


# Demonstrar autenticação de mensagens com HMAC

def demonstrar_mensagens_hmac():

    Antony = Usuario("Antony", "ULTRASECRETO")
    Mariana = Usuario("Mariana", "ULTRASECRETO")
    Alex = Usuario("Alex")

    mensagem_Antony = Antony.enviar_mensagem(
        "Olá, esta é uma mensagem segura!"
    )

    print("\nVerificação da mensagem original:")
    Mariana.verificar_mensagem(mensagem_Antony)

    print("\nTentativa de adulteração:")
    mensagem_alterada = Alex.alterar_mensagem(
        mensagem_Antony.copy()
    )

    Mariana.verificar_mensagem(mensagem_alterada)


# Executar testes de segurança

def executar_testes_seguranca():

    print("\n--- Testes de Segurança ---")

    if not validar_chaves():
        print("Gere um par de chaves antes de executar os testes.")
        return

    resultados = []

    nome_arquivo = "arquivo_teste.txt"

    with open(nome_arquivo, "w", encoding="utf-8") as arquivo:
        arquivo.write("Arquivo utilizado para os testes de segurança.")

    # Teste de criptografia e descriptografia

    try:
        resultado = criptografar(nome_arquivo)

        if resultado:
            resultado = descriptografar(nome_arquivo + ".cofre")

        resultados.append(("Criptografia e descriptografia", resultado))

    except Exception as erro:
        print("Erro no teste de criptografia:", erro)
        resultados.append(("Criptografia e descriptografia", False))

    # Teste de assinatura digital

    try:
        resultado = assinar_arquivo(nome_arquivo)

        if resultado:
            resultado = verificar_assinatura(nome_arquivo)

        resultados.append(("Assinatura digital", resultado))

    except Exception as erro:
        print("Erro no teste de assinatura:", erro)
        resultados.append(("Assinatura digital", False))

    # Teste de adulteração

    try:
        resultado = testar_adulteracao(nome_arquivo)

        resultados.append(("Detecção de adulteração", resultado))

    except Exception as erro:
        print("Erro no teste de adulteração:", erro)
        resultados.append(("Detecção de adulteração", False))

    # Teste de autenticação HMAC

    try:
        Antony = Usuario("Antony", "ULTRASECRETO")
        Mariana = Usuario("Mariana", "ULTRASECRETO")

        mensagem = Antony.enviar_mensagem("Teste HMAC")

        resultado_original = Mariana.verificar_mensagem(mensagem)

        mensagem_alterada = Antony.alterar_mensagem(mensagem.copy())

        resultado_alterado = Mariana.verificar_mensagem(
            mensagem_alterada
        )

        resultado = resultado_original and not resultado_alterado

        resultados.append(("Autenticação HMAC", resultado))

    except Exception as erro:
        print("Erro no teste HMAC:", erro)
        resultados.append(("Autenticação HMAC", False))

    # Teste de certificado

    try:
        if not os.path.exists("certificado.pem"):
            gerar_certificado()

        resultado = validar_certificado()

        resultados.append(("Certificado digital", resultado))

    except Exception as erro:
        print("Erro no teste de certificado:", erro)
        resultados.append(("Certificado digital", False))

    # Resultado final

    print("\n--- Resultado dos Testes ---")

    for nome, resultado in resultados:
        if resultado:
            print(nome + ": APROVADO")
        else:
            print(nome + ": REPROVADO")

    aprovados = sum(1 for nome, resultado in resultados if resultado)

    print(f"\nTotal: {aprovados}/{len(resultados)} testes aprovados.")


# Menu principal

# Menu principal do programa
def main():

    while True:

        print("\n===== COFRE DE ARQUIVOS =====")
        print("1 - Gerar par de chaves")
        print("2 - Criar arquivo")
        print("3 - Criptografar arquivo")
        print("4 - Descriptografar arquivo")
        print("5 - Assinar arquivo digitalmente")
        print("6 - Verificar assinatura")
        print("7 - Testar adulteração")
        print("8 - Gerenciar certificados")
        print("9 - Executar testes de segurança")
        print("10 - Demonstrar autenticação HMAC")
        print("11 - Armazenamento do cofre")
        print("0 - Sair")

        opcao = input("Escolha uma opção: ")

        try:

            if opcao == "1":
                gerar_chaves()

            elif opcao == "2":
                criar_arquivo()

            elif opcao == "3":
                nome = input("Nome do arquivo: ")

                # Guarda o .cofre automaticamente após criptografar
                if criptografar(nome):
                    armazenamento_cofre.salvar_no_cofre(nome + ".cofre")

            elif opcao == "4":
                nome = input("Nome do arquivo .cofre: ")
                descriptografar(nome)

            elif opcao == "5":
                nome = input("Nome do arquivo: ")
                assinar_arquivo(nome)

            elif opcao == "6":
                nome = input("Nome do arquivo: ")
                verificar_assinatura(nome)

            elif opcao == "7":
                nome = input("Nome do arquivo: ")
                testar_adulteracao(nome)

            elif opcao == "8":
                gerenciar_certificados()

            elif opcao == "9":
                executar_testes_seguranca()

            elif opcao == "10":
                demonstrar_mensagens_hmac()

            elif opcao == "11":
                armazenamento_cofre.menu_armazenamento()

            elif opcao == "0":
                print("Encerrando o programa.")
                break

            else:
                print("Opção inválida.")

        except FileNotFoundError:
            print("Arquivo não encontrado.")

        except InvalidTag:
            print("Não foi possível descriptografar. O arquivo pode ter sido alterado.")

        except Exception as erro:
            print("Ocorreu um erro:", erro)


# Inicia o programa
if __name__ == "__main__":
    main()