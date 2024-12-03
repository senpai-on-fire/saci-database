from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import TelemetryHigh, ControllerHigh, Device, CyberComponentBase, Wifi, Controller, Motor, WebClientHigh
from saci.modeling.state import GlobalState
from saci_db.vulns.deauth_vuln import WiFiDeauthVuln


class WiFiDeauthDosCPV(CPV):
    NAME = "WiFi Deauthentication DOS attack"

    def __init__(self):
        wifi_deauth_vuln = WiFiDeauthVuln()
        super().__init__(
            required_components=[
                wifi_deauth_vuln.component,
                TelemetryHigh(),
                ControllerHigh(),
                WebClientHigh(),
                Motor()
            ],
            entry_component=TelemetryHigh(powered=True),
            vulnerabilities=[wifi_deauth_vuln],
            initial_conditions={
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
            exploit_steps=[
                "set the Wi-Fi card into monitor mode and find the BSSID and channel number for the CPS's Wi-Fi network.",
                "The attacker sends a deauthentication packet to the control computer."
                ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV001/HII-NGP1AROV1ARR03-CPV001-20240828.docx"]
        )

    def is_possible_path(self, path: List[Type[CyberComponentBase]]):
        required_components = [Wifi, Controller, WebClientHigh, Motor]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # The goal state is now defined as a mission failure due to DoS on TelemetryHigh and ControllerHigh
        telemetry_dos = self.is_component_dos(state, TelemetryHigh)
        controller_dos = self.is_component_dos(state, ControllerHigh)
        webclient_dos = self.is_component_dos(state, WebClientHigh) 
        motor_dos = self.is_component_dos(state, Motor)

        # Mission failure occurs if both TelemetryHigh and ControllerHigh experience DoS
        return telemetry_dos and controller_dos and webclient_dos and motor_dos

    def is_component_dos(self, state: GlobalState, component_type):
        # Check if a component of type component_type is experiencing a DoS
        for component in state.components:
            if isinstance(component, component_type):
                if component.powered and not component.connected:
                    return True
        return False
