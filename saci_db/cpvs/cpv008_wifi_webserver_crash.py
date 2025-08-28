from saci.modeling import CPV
from saci.modeling.device import (
    Wifi,
    Controller,
    Motor,
    WebServer,
)

from saci_db.vulns.wifi_knowncreds_vuln import WifiKnownCredsVuln
from saci_db.vulns.weak_application_auth_vuln import WeakApplicationAuthVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector

from saci.modeling.state import GlobalState


class WifiWebCrashCPV(CPV):
    NAME = "The Crashing the CPS from Webserver and via Wifi"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Wifi(), # This is the entry component (Required)
                WebServer(), # This is a required vulnerable component (Required)
                # Controller(), # This is the Arduino Uno R4 WiFi which hosts the webserver (Not Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                Controller(), # This is the Arduino Uno R3 which hosts the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
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
                "Operating mode": "Manual",
            },
            
            attack_requirements=["Computer", "Hardcoded credentials"],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Long HTTP GET Requests Injection",
                    # the external input will be the long http request from the attacker's web client
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Wifi()),
                    required_access_level="Proximity",
                    configuration={"duration": "permanent"},
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of control",
                    description="The user can not stop the CPS while driving",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                    "Reverse-engineer the CPS firmware to determine if the ICMP protocol is used",
                    "Analyze the CPS control logic to assess how disconnection impacts CPS dynamics.",
                "TA2 Exploit Steps",
                    "Implement a simulation of an ICMP flooding attack on the CPS network.",
                    "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                    "Check with TA1 to determine the desired impact on control.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                    "Connect to rover Wi-Fi using hardcoded credentials",
                    "Issue a long HTTP GET request (at least 26,000 characters) to the webserver address",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/NGC1B-rover-CPVs/blob/main/CPV003/HII-NGP1AROV1ARR03-CPV003-20240828.docx"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
