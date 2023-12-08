import scapy.all as scapy
import json
import logging
import os
import socket
import time

# Antônio Amadeu Dall'Agnol Rohr e Rafael Carneiro Pregardier
# Gerência de Redes

# Configure o logger para controlar as mensagens de registro
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

discovery_history = {}
current_directory = os.path.dirname(os.path.abspath(__file__))
results = []

def load_discovery_history():
    # Carrega o histórico de descobertas de um arquivo JSON
    try:
        with open(f"{current_directory}/discovery_history.json", "r") as arp_file:
            history = json.load(arp_file)
        return history
    except FileNotFoundError:
        return {}

def save_discovery_history(results):
    # Salva o histórico de descobertas em um arquivo JSON
    with open(f"{current_directory}/discovery_history.json", "w") as arp_file:
        json.dump(results, arp_file, indent=4)

def load_mac_vendors():
    # Carrega o arquivo JSON que contém os prefixos de endereço MAC para cada fabricante
    try:
        with open(f"{current_directory}/mac-vendors-export.json", "r", encoding='utf-8') as file:
            mac_vendors = json.load(file)
        return mac_vendors
    except Exception as e:
        print(f"Erro ao carregar o arquivo mac-vendors-export.json: {str(e)}")
        return {}
    
def get_local_ip():
    # Obtém o endereço IP local do dispositivo
    try:
        # Cria um socket UDP para encontrar o IP local
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.1)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Erro ao obter o endereço IP local: {str(e)}")
        return None
    
def is_router(ip):
    # Verifica se um dispositivo é um roteador
    # Se o ip conter no final 0.1 ou 0.254, é um roteador
    if ip.endswith(".1") or ip.endswith(".254"):
        return True
    
def format_mac(mac_address):
    # Formata o endereço MAC com os dois pontos (:)
    formatted_mac = ":".join([mac_address[i:i+2] for i in range(0, len(mac_address), 2)])
    return formatted_mac

def get_manufacturer(mac_address, mac_vendors):
    # Consulta o arquivo JSON para encontrar o fabricante com base no endereço MAC
    formatted_mac = format_mac(mac_address)
    for item in mac_vendors:
        if formatted_mac.startswith(item['macPrefix']):
            return item['vendorName']
    return "Desconhecido"

# Função para snifar pacotes ARP
def sniff_arp_packets(interface, execution_time):
    scapy.sniff(iface=interface, store=False, prn=process_arp_packet, timeout=execution_time)

def process_arp_packet(packet):
    # Observa os pacotes ARP trocados na rede    
    try:
        if packet.haslayer(scapy.ARP):
            arp_packet = packet[scapy.ARP]
            device_name = socket.getfqdn(arp_packet.psrc)
            device_ip = arp_packet.psrc
            device_mac = arp_packet.hwsrc
            mac_address_cleaned = device_mac.replace(":", "").upper()
            manufacturer = get_manufacturer(mac_address_cleaned, mac_vendors)
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            result = {
                "Nome": device_name,
                "IP": device_ip,
                "MAC": device_mac,
                "Fabricante": manufacturer,
                "Primeira Descoberta": current_time,
                "Tipo": "Roteador" if is_router(device_ip) else "Host"
            }

            if result['IP'] not in [entry.get('IP') for entry in results]:
                results.append(result)

                logging.info(f"Pacote ARP Trocado - Nome: {device_name} | IP: {device_ip} | MAC: {device_mac} | Fabricante: {manufacturer} | Primeira Descoberta: {current_time} | Tipo: {result['Tipo']}")

    except Exception as e:
        logging.error(f"Ocorreu um erro ao observar pacotes ARP: {str(e)}")

def observe_arp_packets(ip, mac_vendors):
    # Observa os pacotes ARP trocados na rede
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]

        for element in answered_list:
            device_name = socket.getfqdn(element[1].psrc)
            device_ip = element[1].psrc
            device_mac = element[1].hwsrc
            mac_address_cleaned = device_mac.replace(":", "").upper()
            manufacturer = get_manufacturer(mac_address_cleaned, mac_vendors)
            current_time = time.strftime("%Y-%m-%d %H:%M:%S")
            
            result = {
                "Nome": device_name,
                "IP": device_ip,
                "MAC": device_mac,
                "Fabricante": manufacturer,
                "Primeira Descoberta": current_time,
                "Tipo": "Roteador" if is_router(device_ip) else "Host"
            }

            results.append(result)

            logging.info(f"Pacote ARP Trocado - Nome: {device_name} | IP: {device_ip} | MAC: {device_mac} | Fabricante: {manufacturer} | Primeira Descoberta: {current_time} | Tipo: {result['Tipo']}")

    except Exception as e:
        logging.error(f"Ocorreu um erro ao observar pacotes ARP: {str(e)}")

from pysnmp.hlapi import *
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher


# ... Outras importações e código existente ...

# Função para responder às solicitações SNMP
def snmp_handler(snmp_engine, execpoint, varBinds, acInfo, indexGenerator):
    print('cu')
    for name, val in varBinds:
        # Verifique o OID solicitado e forneça o valor correspondente
        if name == (1, 3, 6, 1, 4, 1, 9999, 1, 1):  # Substitua pelo seu OID
            return ObjectType(ObjectIdentity(name), 'hello-world')

# Adicione o manipulador SNMP para SET
setCmd(SnmpEngine, CommunityData('private'), UdpTransportTarget(('127.0.0.1', 161)),
       ContextData(), ObjectType(ObjectIdentity('1.3.6.1.4.1.9999.1.1')),
       cbFun=snmp_handler)
# ... Código existente ...

if __name__ == "__main__":
    try:
        local_ip = get_local_ip()
        history = load_discovery_history()
        new_results = []
        interface = input("Digite o nome da interface de rede: ")
        barramento = "/" + (input("Digite o número do barramento: "))
        file_name_last_scan = ["ping_broadcast_last_scan.json", "arp_last_scan.json"]

        if local_ip:
            target_ip = local_ip + barramento
            print(target_ip)
            mac_vendors = load_mac_vendors()

            print("Escolha o modo de descoberta:")
            print("1. Descoberta por ping broadcast")
            print("2. Descoberta por pacotes ARP")
            print("3. Descoberta SNMP")

            option = 3

            if option == 1:
                observe_arp_packets(target_ip, mac_vendors)
            elif option == 2:
                print("Digite o tempo de execução do sniffer (em segundos): ")
                execution_time = int(input("Tempo: "))
                sniff_arp_packets(interface, execution_time)
            elif option == 3:
                # Criar o objeto SnmpEngine
                snmp_engine = SnmpEngine()
        
                # Adicione o manipulador SNMP para GET
                getCmd(snmp_engine, CommunityData('public'), UdpTransportTarget(('127.0.0.1', 161)),
                       ContextData(), ObjectType(ObjectIdentity('1.3.6.1.4.1.9999.1.1')),
                       cbFun=snmp_handler)

                # Inicie o dispatcher SNMP

                snmp_engine.transportDispatcher.jobStarted(1)  # Substitua '1' pelo número correto do trabalho

                # Continue com o código aqui, sem chamar runDispatcher()

            else:
                print("Opção inválida.")

            # ... Código existente ...

    except Exception as e:
        logging.error(f"Ocorreu um erro ao executar o programa: {str(e)}")