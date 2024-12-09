from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, Motor, WebServer, ESC
from saci_db.vulns.knowncreds import WifiKnownCredsVuln
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector

from saci.modeling.state import GlobalState


class WebCrashCPV(CPV):
   
    NAME = "The Crash-via-Web CPV"

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
            exit_component=Motor(),

            vulnerabilities=[WifiKnownCredsVuln(), WeakApplicationAuthVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Manual"
            },

            attack_requirements=["Computer","Hardcoded credentials"],
            attack_vectors = [BaseAttackVector(name="Long HTTP GET Requests Injection", 
                                               # the external input will be the long http request from the attacker's web client
                                               signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                                               required_access_level="Proximity",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='The user can not stop the CPS while driving')],

            exploit_steps=[
                "Connect to rover Wi-Fi using hardcoded credentials",
                "Issue a long HTTP GET request (at least 26,000 characters) to the webserver address",
            ],
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
