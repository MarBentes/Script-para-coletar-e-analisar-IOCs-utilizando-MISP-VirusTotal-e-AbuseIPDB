import os
import http.client
import ssl
import json
import time
import base64

# Função para exibir um cabeçalho estilizado
def print_header(text):
    print("=" * 60)
    print(f"{text:^60}")
    print("=" * 60)

# Função para obter a entrada do usuário com validação
def get_input(prompt, valid_options=None):
    while True:
        user_input = input(prompt).strip()
        if valid_options and user_input not in valid_options:
            print(f"Opção inválida. Escolha entre: {', '.join(valid_options)}")
        elif valid_options is None and not user_input:
            print("Entrada inválida. Não pode estar vazia.")
        else:
            return user_input

# Parte 1: Obter as informações do usuário
print_header("Configuração do Script de Coleta e Análise de IOCs")

# Pedir ao usuário para inserir a chave de autenticação do MISP
auth_key_misp = get_input("Digite sua AUTH key do MISP: ")

# Pedir ao usuário para inserir a chave de API do VirusTotal
api_key_virustotal = get_input("Digite sua API key do VirusTotal: ")

# Pedir ao usuário para inserir a chave de API do AbuseIPDB
api_key_abuseipdb = get_input("Digite sua API key do AbuseIPDB: ")

# Parte 2: Interação para obter valores de ip-src, ip-dst, url, md5, sha1, sha256, tags e período em dias
attribute_type = get_input("Selecione o tipo de ATRIBUTO (ip-src, ip-dst, url, md5, sha1, sha256): ", ["ip-src", "ip-dst", "url", "md5", "sha1", "sha256"])

# Pergunta ao usuário para inserir a tag
tag = get_input("Digite a TAG desejada: ")

# Pergunta ao usuário para inserir o período em dias
period_days = get_input("Digite o período em DIAS: ")

# Pergunta ao usuário para inserir a porcentagem mínima de reputação no AbuseIPDB
min_reputation = int(get_input("Digite a porcentagem mínima de reputação no AbuseIPDB: "))

# URL fixa do servidor MISP
server_name = "s1mspp01"
path = f"/attributes/text/download/{attribute_type}/tags:{tag}/last:{period_days}D"

# Parte 3: Baixar dados do servidor MISP e salvar em {attribute_type}_MISP.txt
print_header("Baixando dados do servidor MISP")

# Define o caminho do diretório
directory_path = "d:/temp"

# Verifica e cria o diretório se não existir
if not os.path.exists(directory_path):
    os.makedirs(directory_path)

# Cabeçalhos para a requisição
headers = {
    "Authorization": auth_key_misp,
    "Accept": "application/json",
    "Content-Type": "application/json"
}

# Caminho onde o arquivo será salvo
output_file_path = os.path.join(directory_path, f"MISP_{attribute_type}.txt")

# Tenta executar a requisição
try:
    # Estabelece uma conexão HTTPS
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(server_name, context=context)
    
    # Faz a requisição GET
    connection.request("GET", path, headers=headers)
    
    # Obtém a resposta
    response = connection.getresponse()
    
    # Lê os dados da resposta
    if response.status == 200:
        data = response.read().decode('utf-8')
        with open(output_file_path, 'w') as file:
            file.write(data)
        print(f"Arquivo salvo em: {output_file_path}")
    else:
        print(f"Falha ao fazer a requisição: {response.status} {response.reason}")
except Exception as e:
    print(f"Falha ao fazer a requisição: {e}")
    print(f"Detalhes do erro: {str(e)}")
    exit(1)
finally:
    # Fecha a conexão
    if 'connection' in locals():
        connection.close()

# Parte 4: Processar o arquivo {attribute_type}MISP.txt no VirusTotal e salvar resultados maliciosos em Virustotal{attribute_type}.txt
print_header("Processando dados no VirusTotal")

# Nome do arquivo de entrada (com lista de IOCs)
input_file = output_file_path
# Nome do arquivo de saída para IOCs maliciosos do VirusTotal
output_file_virustotal = os.path.join(directory_path, f'Virustotal_{attribute_type}.txt')

# Função para consultar o VirusTotal
def query_virustotal(ioc, attribute_type):
    url = 'www.virustotal.com'
    if attribute_type in ["ip-src", "ip-dst"]:
        path = f'/api/v3/ip_addresses/{ioc}'
    elif attribute_type in ["md5", "sha1", "sha256"]:
        path = f'/api/v3/files/{ioc}'
    elif attribute_type == "url":
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        path = f'/api/v3/urls/{url_id}'
    headers = {
        'x-apikey': api_key_virustotal
    }
    while True:
        try:
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(url, context=context)
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status == 200:
                return json.loads(response.read().decode('utf-8'))
            elif response.status == 429:
                print(f"Taxa de solicitação excedida para o IOC: {ioc}. Aguardando...")
                time.sleep(60)  # Espera 60 segundos antes de tentar novamente
            elif response.status == 404:
                print(f"Recurso não encontrado para o IOC: {ioc}.")
                return None
            else:
                print(f"Falha ao consultar o VirusTotal para o IOC: {ioc} - Status: {response.status} {response.reason}")
                return None
        except Exception as e:
            print(f"Erro ao consultar o VirusTotal: {e}")
            return None
        finally:
            connection.close()

# Ler a lista de IOCs do arquivo de entrada
with open(input_file, 'r') as file:
    iocs = file.read().splitlines()

# Consultar cada IOC no VirusTotal e salvar os IOCs maliciosos no arquivo de saída do VirusTotal
malicious_iocs_virustotal = []
for ioc in iocs:
    result = query_virustotal(ioc, attribute_type)
    if result is not None:
        attributes = result['data']['attributes']
        if 'last_analysis_stats' in attributes:
            analysis_stats = attributes['last_analysis_stats']
            malicious = analysis_stats.get('malicious', 0)
            if malicious > 0:
                malicious_iocs_virustotal.append(ioc)

# Salvar os IOCs maliciosos do VirusTotal em um arquivo de texto
with open(output_file_virustotal, 'w') as file:
    for ioc in malicious_iocs_virustotal:
        file.write(ioc + '\n')

print(f"IOCs maliciosos do VirusTotal salvos em '{output_file_virustotal}'")


# Parte 5: Verificar reputação dos IOCs maliciosos no AbuseIPDB (se aplicável) e salvar aqueles com reputação >= min_reputation% em {attribute_type}_IPabuse_Block.txt
print_header("Verificando reputação dos IOCs no AbuseIPDB")

# Nome do arquivo de saída para IOCs maliciosos do AbuseIPDB
output_file_abuseipdb = os.path.join(directory_path, f'IOCs_{attribute_type}_Block.txt')

if attribute_type in ["ip-src", "ip-dst"]:
    # Função para verificar se um IP é malicioso no AbuseIPDB
    def is_malicious_ip_abuseipdb(ip):
        url = 'api.abuseipdb.com'
        path = f'/api/v2/check?ipAddress={ip}'
        headers = {
            "Key": api_key_abuseipdb,
        }
        try:
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(url, context=context)
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            result = json.loads(response.read().decode('utf-8'))
            if result.get("data", {}).get("abuseConfidenceScore", 0) >= min_reputation:
                return True
            return False
        except Exception as e:
            print(f"Erro ao consultar o AbuseIPDB: {e}")
            return False
        finally:
            connection.close()

    # Ler a lista de IPs maliciosos do VirusTotal
    with open(output_file_virustotal, 'r') as file:
        malicious_iocs_virustotal = file.read().splitlines()

    # Verifique se cada IP é malicioso no AbuseIPDB
    malicious_iocs_abuseipdb = [ioc for ioc in malicious_iocs_virustotal if is_malicious_ip_abuseipdb(ioc)]

    # Salvar os IOCs maliciosos do AbuseIPDB em um arquivo de texto
    with open(output_file_abuseipdb, 'w') as file:
        for ioc in malicious_iocs_abuseipdb:
            file.write(ioc + '\n')

    print(f"IOCs maliciosos do AbuseIPDB salvos em '{output_file_abuseipdb}'")
else:
    # Se o atributo não for IP, simplesmente copie os maliciosos do VirusTotal para o arquivo final
    with open(output_file_abuseipdb, 'w') as file:
        for ioc in malicious_iocs_virustotal:
            file.write(ioc + '\n')

    print(f"IOCs maliciosos salvos em '{output_file_abuseipdb}'")

# Função de assinatura oculta
def _developer_signature():
    return "Developed by Marcelo Bentes"

# Assinatura do autor
print_header("Script de Coleta e Análise de IOCs")
print("Desenvolvido por Marcelo Bentes")
print("=" * 60)

# Chamada da função de assinatura oculta
_signature = _developer_signature()