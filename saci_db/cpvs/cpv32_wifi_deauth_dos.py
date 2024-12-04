from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, Motor, WebServer, CyberComponentBase
from saci_db.vulns.deauth_vuln import WiFiDeauthVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

#This is to model the attack in the CX-10W drone as described by the referenced paper,
#It ended up looking exactly the same as cpv03_deauth_dos in Holybroclass

class WiFiDeauthDosCPV(CPV):
    
    NAME = "WiFi Deauthentication DOS attack CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                Motor(),
            ],
            entry_component = Wifi(),
            exit_component = Motor(),

            vulnerabilities =[WiFiDeauthVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Manual"
            },
            
            attack_requirements=[
                "Computer"
                "WIFI card with monitor mode"
                "Aircrack-ng software",
                "WIFI Credentials"
            ],

            attack_vectors = [BaseAttackVector(name="deauthenticate Wifi client", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               #  aireplay-ng -0 0 -a [BSSID] [interface_name]
                                               configuration={"BSSID":"CPS's accsess point","interface_name":"wireless","other args":"-0 0 -a"},
                                                )],
            attack_impacts = [BaseAttackImpact(category='Denial of control',
                                               description='The user can not stop the CPS')],
            exploit_steps=[
                "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                "Send a deauthentication packet to the WIFI Interface."
                ],
                
            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279&tag=1"]
        )


    def is_possible_path(self, path: List[Type[CyberComponentBase]]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass