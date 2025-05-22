from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Wifi, Controller, Motor, PWMChannel, WebServer, ESC, CANBus, CANTransceiver, CANShield

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
                CANTransceiver(),
                CANBus(),
                CANShield(),
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
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi and HTT protocols implements any security mechanisms",
                    "Identify if the firmware has failsafe mechanisms to recover from malicious HTTP requests.",
                    "Analyze the CPS control logic to assess how malicious HTTP requests manipulate the CPS movements.",
                    "Create models for the following components: Wifi, Webserver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious HTTP request injection the CPS."
                    "Use a fuzzing tool to fuzz the functions and generate a malicious HTTP request that manipulates the move button.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use Optical imaging tools to catalog all of the components on the rover.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there’s a WIFI component.",
                    "Check if there are hardcoded credentials for connecting to the Wi-Fi network.",
                    "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                    "Power CPS on",
                    "On attacker computer, connect to CPS Wi-Fi network with SSID “FuelSource Wifi” and using hardcoded credentials “C6H12O612345”",
                    "On operator computer, connect to CPS Wi-Fi in the same manner",
                    "On operator computer, using a web browser, navigate to http://192.168.4.1/",
                    "Observe that the CPS remains idle",
                    "On attacker computer, using a web browser, navigate to http://192.168.4.1/",
                    "On attacker computer, click either of the drive buttons",
                    "Ensure CPS begins to drive",
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-CPS-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
