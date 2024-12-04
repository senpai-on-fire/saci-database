from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import TelemetryHigh, ControllerHigh, Device, CyberComponentBase, Wifi, Controller, Motor, WebClientHigh
from saci.modeling.state import GlobalState
from saci_db.vulns.deauth_vuln import WiFiDeauthVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact


class WiFiDeauthDosCPV(CPV):
    NAME = ""

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
                "Speed": "Any",
                "Environment": "Any",
                "Software state (RemoteController)": "On",
                "Software state (CPSController)": "Moving",
                "Operating mode": "???"
            },
            attack_requirements=[
                "Attacker computer",
                "Firmware for the Renesas RA4M1 processor on the Arduino Uno R4 to retrieve hard coded credentials."
            ],
            attack_vectors = [BaseAttackVector(name="Move button", 
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=wifi_deauth_vuln.component, modality="network"),
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
