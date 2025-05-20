from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import Wifi, Controller, Telemetry, Motor, WebServer, WebClient, PWMChannel, ESC

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln

from saci.modeling.state import GlobalState

class WifiWebStopCPV(CPV):
    
    NAME = "The Stop the CPS from Webserver and via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                WebServer(),
                Controller(),
                Telemetry(),
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
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi and HTT protocols implements any security mechanisms",
                    "Identify if the firmware has failsafe mechanisms to recover from deauthentication or if it enters a critical state.",
                    "Analyze the CPS control logic to assess how malicious HTTP requests manipulate the CPS movements.",
                    "Create models for the following components: Wifi, Webserver, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"
                
                "TA2 Exploit Steps",
                    "Create an automata to simulate a malicious HTTP request injection the CPS."
                    "Use a fuzzing tool to fuzz the functions and generate a malicious HTTP request that manipulates the stop button.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use Optical imaging tools to catalog all of the components on the rover.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there’s a WIFI component.",
                    "Check if there are hardcoded credentials for connecting to the Wi-Fi network.",
                    "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                    "Power CPS on",
                    "On attacker computer, connect to rover Wi-Fi network with SSID “FuelSource Wifi” and using hardcoded credentials “C6H12O612345”",
                    "On operator computer, connect to rover Wi-Fi in the same manner",
                    "On operator computer, using a web browser, navigate to http://192.168.4.1/",
                    "On operator computer, click either of the drive buttons",
                    "Observe rover begins to drive",
                    "On attacker computer, using a web browser, navigate to http://192.168.4.1/Stop before mission has completed",
                    "Observe that the rover stops"

            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV009/HII-NGP1AROV1ARR03-CPV009-20240911.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
