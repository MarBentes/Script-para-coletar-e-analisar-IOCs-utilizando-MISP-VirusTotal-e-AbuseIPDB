# Automação de Coleta e Análise de IOCs

## Introdução

Este projeto foi desenvolvido para automatizar a coleta e análise de Indicadores de Comprometimento (IOCs) utilizando a plataforma MISP e as ferramentas VirusTotal e AbuseIPDB. O objetivo é aumentar a assertividade na identificação de ameaças cibernéticas e facilitar o consumo de feeds de bloqueio por ferramentas de proteção.

## Funcionalidades

O script executa as seguintes etapas:

1. **Coleta de IOCs do MISP**: Utiliza critérios definidos pelo usuário, como tipo de atributo (IP, URL, hash), tags e período em dias.
2. **Análise com VirusTotal**: Verifica cada IOC coletado e identifica quais são maliciosos, salvando-os em um arquivo específico.
3. **Verificação com AbuseIPDB**: Valida a reputação dos IOCs maliciosos no AbuseIPDB, garantindo que apenas aqueles com alta probabilidade de serem maliciosos sejam mantidos.

## Tecnologias Usadas

- **Linguagem**: Python
- **Bibliotecas**: os, http.client, ssl, json, time, base64
- **Plataformas**: MISP, VirusTotal, AbuseIPDB

## Instalação

1. Clone o repositório:
   ```bash
   git clone https://github.com/MarBentes/Script-para-coletar-e-analisar-IOCs-utilizando-MISP-VirusTotal-e-AbuseIPDB.git
   
2. Navegue até o diretório do projeto:

   cd Script-para-coletar-e-analisar-IOCs-utilizando-MISP-VirusTotal-e-AbuseIPDB

Como Usar

1. Configuração: O script solicitará as chaves de autenticação para o MISP, VirusTotal e AbuseIPDB, além do tipo de atributo, tag, período em dias e a porcentagem mínima de reputação no AbuseIPDB.

2. Execução: Execute o script:

   python misp_ioc.py

3. Coleta de IOCs do MISP: Insira o nome do seu servidor MISP na variável server_name no script.

   exemplo:
server_name = "nome do seu servidor MISP"
path = f"/attributes/text/download/{attribute_type}/tags:{tag}/last:{period_days}D"


## Contribuição
Se você tiver sugestões ou encontrar problemas, sinta-se à vontade para abrir uma issue ou enviar um pull request.

## Licença
Este projeto está licenciado sob a Licença MIT - veja o arquivo LICENSE para detalhes.

## Contato
Para mais informações, entre em contato comigo pelo LinkedIn. www.linkedin.com/in/marcelo-bentes-79381963
