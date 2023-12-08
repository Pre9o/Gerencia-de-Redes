#Coding with UTF8

"""
Author : Simke Anthony
Company : Haute ecole de la province du Hainaut
Departement : Departement des sciences et technologies
Etudes : bachiler en informatique est systèmes, réseaux et télécommunication
Orientation : développement
Context : Snmp agent prototypage
"""

from agent.SnmpAgent import SnmpAgent


if __name__ == '__main__':
    agent = SnmpAgent("127.0.0.1", 162)
    agent.run(1)
    

