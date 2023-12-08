from pysnmp.hlapi import *

class SnmpManager:
    def __init__(self, agent_ip, agent_port, version, community):
        self.agent_ip = agent_ip
        self.agent_port = agent_port
        self.version = version
        self.community = community

    def get(self, oid):
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(SnmpEngine(),
                   CommunityData(self.community, mpModel=self.version),
                   UdpTransportTarget((self.agent_ip, self.agent_port)),
                   ContextData(),
                   ObjectType(ObjectIdentity(oid)))
        )

        if errorIndication:
            print(f"Error: {errorIndication}")
        elif errorStatus:
            print(f"Error: {errorStatus}")
        else:
            for varBind in varBinds:
                print(f"{varBind.prettyPrint()}")

if __name__ == "__main__":
    agent_ip = "127.0.0.1"  # Endereço IP do agente SNMP
    agent_port = 162  # Porta do agente SNMP
    version = 1  # Versão SNMP (pode ser 1 ou 3)
    community = "public"  # Comunidade SNMP (substitua pela sua)

    manager = SnmpManager(agent_ip, agent_port, version, community)

    # OID de exemplo para obter informações do sistema
    system_info_oid = "1.3.6.1.2.1"

    manager.get(system_info_oid)
