from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Wifi, Controller, Motor, PWMChannel, WebServer, WebClient, ESC

from saci.modeling.communication import ExternalInput

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class WifiWebMoveCPV(CPV):
    
    NAME = "The Move the CPS from Webserver and via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                Controller(),
                PWMChannel(), 
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
                "CPSController": "Idle",
                "Operating mode": "Manual"
            },
            attack_requirements=[
                "Attacker computer",
                "Firmware for the Renesas RA4M1 processor on the Arduino Uno R4 to retrieve hard coded credentials."
            ],
            attack_vectors = [BaseAttackVector(name="Move Button Manipulation via HTTP Requests Injection", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Manipulation of control.',
                                               description='The CPS starts driving without the operator control')],

            exploit_steps=[
                "Connect to Wi-Fi network using the hardcoded credentials”",
                "Using a web browser, navigate to webserver IP address",
                "Observe that the cps remains idle",
                "Click either of the drive buttons",
                "Ensure the rover begins to drive"
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
