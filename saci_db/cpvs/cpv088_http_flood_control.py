from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, Motor, WebServer, PWMChannel, ESC, Telemetry

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector

from saci.modeling.state import GlobalState

#Notes
# It is quite similar to It is quite similar to this one from the previous rover 
# https://github.com/senpai-on-fire/saci-database/blob/main/saci_db/cpvs/cpv008_wifi_webserver_crash.py
 
class WifiWebCrashCPV(CPV):

    NAME = "Denial of Service and Control Hijacking via Webserver Flooding over Wi-Fi"

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
            exit_component=Motor(),

            vulnerabilities=[WifiKnownCredsVuln(), WeakApplicationAuthVuln()],

            initial_conditions={
                "Position": "Stationary",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Idle",
                "Operating mode": "Manual"
            },

            attack_requirements=["Two Computers", "Hardcoded credentials", "Hex wrench"],

            attack_vectors=[
                BaseAttackVector(
                    name="HTTP Request Flooding DoS",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    configuration={"request_type": "HTTP GET", "frequency": "High", "duration": "Continuous"},
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category='Loss of control',
                    description='Operator is unable to access the rover’s controls via web interface; attacker retains partial or full control.'
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Perform software reverse engineering on rover firmware to identify the web interface loop operations.",
                    "Identify how HTTP GET requests are processed differently compared to previous rover firmware versions.",
                    "Determine the control variables relevant to request handling and their timing in the firmware logic.",

                "TA2 Exploit Steps",
                    "Develop an attacker script (e.g., cprj2.py) to flood the webserver with HTTP GET requests continuously.",
                    "Test the script initially in a controlled environment to validate the continuous denial of service condition.",
                    "Ensure the attacker maintains control even when the operator is locked out.",

                "TA3 Exploit Steps",
                    "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                    "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                    "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                    "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                    "Run attacker script to flood rover with HTTP GET requests.",
                    "Verify operator's web interface becomes non-responsive.",
                    "Confirm attacker control through initiation of rover drive mission despite operator lockout.",
                    "Terminate attacker script to verify immediate recovery of the operator web interface.",
                    "Power off rover by rotating the power block clockwise until LEDs turn off.",
            ],

            associated_files=["DOS with Attacker Commands-1.pdf", "cprj2.py"],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV020/HII-NGP1AROV2ARR05-CPV020-20250514.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        #TODO
        #return state.component_states[WebServer].availability == False and state.component_states[Controller].accessibility == "AttackerOnly"
        pass
      
    
