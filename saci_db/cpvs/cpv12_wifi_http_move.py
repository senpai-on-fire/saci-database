from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import CyberComponentBase, Wifi, Controller, Motor, WebServer

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci_db.vulns.deauth_vuln import WeakApplicationAuthVuln
from saci_db.vulns.knowncreds import WifiKnownCredsVuln
from saci.modeling.communication import ExternalInput
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln



class WebMovCPV(CPV):
    NAME = "The Move-via-the-web CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                Motor(),
            ],
            entry_component=Wifi(),
            exist_component= Motor(),

            vulnerabilities=[WifiKnownCredsVuln(), WeakApplicationAuthVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state (RemoteController)": "On",
                "Software state (CPSController)": "Idle",
                "Operating mode": "Manual"
            },
            attack_requirements=[
                "Attacker computer",
                "Firmware for the Renesas RA4M1 processor on the Arduino Uno R4 to retrieve hard coded credentials."
            ],
            attack_vectors = [BaseAttackVector(name="Move button", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst= WeakApplicationAuthVuln().component, modality="network"),
                                               required_access_level="proximity",
                                               configuration={"duration": "permanant"},
                                                )],  
            attack_impact = [BaseAttackImpact(category='Manipulation of control.',
                                               description='The CPS starts driving without the operator control')],

            exploit_steps=[
                "1. connect to Wi-Fi network with SSID “FuelSource Wifi” and using hardcoded credentials “C6H12O612345”",
                "2. using a web browser, navigate to http://192.168.4.1/",
                "3. Observe that the cps remains idle",
                "4. click either of the drive buttons",
                "5. Ensure the rover begins to drive"
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"]
        )

    def is_possible_path(self, path: List[Type[CyberComponentBase]]):
        required_components = [Wifi, WebServer, Controller, Motor]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True
