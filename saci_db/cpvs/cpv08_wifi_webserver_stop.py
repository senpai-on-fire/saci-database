from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import (CyberComponentBase, Controller, Wifi, Motor)

from saci.modeling.state import GlobalState
from saci_db.vulns.knowncreds import WifiKnownCredsVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector


from saci_db.vulns.noaps import NoAPSVuln


class WebStopCPV(CPV):
   
    NAME = "The Stop via the Web CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                Controller(),
                Motor(),
            ],

            entry_component=Wifi(),
            vulnerabilities=[WifiKnownCredsVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Mission" # Check with Junchi
            },

            attack_requirements=["Attacker computer.","Hardcoded credentials"],
            attack_vectors = [BaseAttackVector(name="long HTTP requests", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=WifiKnownCredsVuln().component, modality="network"),
                                               required_access_level="proximity",
                                               configuration={"duration": "permanant"},
                                                )],  
            attack_impact = [BaseAttackImpact(category='Loss of control',
                                               description='The user can not stop the CPS while driving')],

            exploit_steps=[
                "Connect to rover Wi-Fi using hardcoded credentials",
                "Issue a long HTTP GET request (at least 26,000 characters) to the webserver address",
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx"]
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
