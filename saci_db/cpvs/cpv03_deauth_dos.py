from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, Motor, WebServer, ESC
from saci_db.vulns.deauth_vuln import WiFiDeauthVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class WiFiDeauthDosCPV(CPV):
    
    NAME = "The WiFi Deauthentication CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                Controller(),
                ESC(),
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

            attack_vectors = [BaseAttackVector(name="Deauthentification Wifi Packets Injection", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               #  aireplay-ng -0 0 -a [BSSID] [interface_name]
                                               configuration={"BSSID":"FuelSource Wifi","interface_name":"wireless","other args":"-0 0 -a"},
                                                )],
            attack_impacts = [BaseAttackImpact(category='Denial of control',
                                               description='The user can not stop the CPS')],
            exploit_steps=[
                "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                "Send a deauthentication packet to the WIFI Interface."
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass