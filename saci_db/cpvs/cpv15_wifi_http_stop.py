from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import CyberComponentBase, Wifi, Controller, Motor, WebServer, ESC

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci_db.vulns.knowncreds import WifiKnownCredsVuln
from saci.modeling.communication import ExternalInput
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln

from saci.modeling.state import GlobalState

class WebStopCPV(CPV):
    
    NAME = "The Stop-via-the-Web CPV"

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
            entry_component=Wifi(),
            exit_component= Motor(),

            vulnerabilities=[WifiKnownCredsVuln(), WeakApplicationAuthVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "driving",
                "Operating mode": "Mission"
            },
            attack_requirements=["Computer","Hardcoded credentials"],
            attack_vectors = [BaseAttackVector(name="Stop Button Manipulation via HTTP Requests Injection", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Manipulation of control.',
                                               description='The CPS stop without the operator input')],

            exploit_steps=[
                "Connect to Wi-Fi network using the hardcoded credentials",
                "Using a web browser, navigate to the webserver IP address",
                "Observe that the CPS remains idle",
                "Click either of the drive buttons",
                "Ensure the rover begins to drive"
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
