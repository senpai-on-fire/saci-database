
from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Wifi, ESC, ICMP
from saci_db.vulns.icmp_vuln import IcmpFloodVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState
from saci_db.vulns.wifi_lack_auth_vuln import LackWifiAuthenticationVuln

from saci.modeling.device import MultiCopterMotor
from saci_db.devices.px4_quadcopter_device import PX4Controller

#This is to model the attack in the ARDrone drone as described by the referenced paper,

class ICMPFloodingCPV(CPV):
    
    NAME = "ICMP flooding attack CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                ICMP(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component = ICMP(),
            exit_component = MultiCopterMotor(),

            vulnerabilities =[LackWifiAuthenticationVuln(),IcmpFloodVuln()],

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
            ],

            attack_vectors = [BaseAttackVector(name="ICMP flooding attack", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=ICMP(),),
                                               required_access_level="Proximity",
                                               configuration={"protocol":"UDP","port":"5556"},
                                                )],
            attack_impacts = [BaseAttackImpact(category='Denial of control',
                                               description='The user can not control the CPS')],
            exploit_steps=[
                "Set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                "join the network",
                "Flood the CPS with TCP SYN on port UDP 5556"
                ],
                
            associated_files=[],
            reference_urls=["https://link.springer.com/article/10.1007/s11416-011-0158-4"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass