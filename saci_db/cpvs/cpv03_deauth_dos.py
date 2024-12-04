from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Telemetry, Controller, CyberComponentBase, Wifi, Controller, Motor, WebClientHigh
from saci.modeling.state import GlobalState
from saci_db.vulns.deauth_vuln import WiFiDeauthVuln
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector


class WiFiDeauthDosCPV(CPV):
    NAME = "WiFi Deauthentication DOS attack CPV"

    def __init__(self):
        wifi_deauth_vuln = WiFiDeauthVuln()
        super().__init__(
            required_components=[
                wifi_deauth_vuln.component,
                Telemetry(),
                WebServer(),
                Controller(),
                Motor()
            ],
            entry_component = Wifi(),
            exit_component = Motor(),

            vulnerabilities =[wifi_deauth_vuln],
            initial_conditions ={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "Software state (RemoteController)": "On",
                "Software state (CPSController)": "Moving",
                "Operating mode": "manual"
            },
            attack_requirements=[
                "Attacker Computer with Wi-Fi card capable of being placed in monitor mode, and the software installed aircrack-ng.",
                "Arduino Uno R4 firmware to get the wifi BSSID"
            ],
            attack_vectors = [BaseAttackVector(name="deauthenticate Wifi client", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=wifi_deauth_vuln.component, modality="network"),
                                               required_access_level="proximity",
                                               configuration={"duration": "permanant"},
                                                )],  
            exploit_steps=[
                "set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                "The attacker sends a deauthentication packet to the control computer."
                ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001/HII-NGP1AROV1ARR03-CPV001-20240828.docx"]
        )

    def is_possible_path(self, path: List[Type[CyberComponentBase]]):
        required_components = [Telemetry, WebServer, Controller, Motor]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True