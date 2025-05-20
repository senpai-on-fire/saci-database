from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.ardscovery_mitm_vuln import ARDiscoveryMitmVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import Wifi, ARDiscovery, Telemetry, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class ARDiscoveryMitM(CPV):

    NAME = "The ARDiscovery Man-in-the-Middle via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                ARDiscovery(),
                ArduPilotController(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(), 
            ],
            entry_component=Wifi(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[LackWifiAuthenticationVuln(), LackWifiEncryptionVuln(), ARDiscoveryMitmVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "Computer with Wi-Fi card supporting monitor mode",
                "Packet crafting tools (e.g., Scapy, arpspoof)",
                "Access to the CPS's network (proximity or Wi-Fi credentials)",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="ARP Cache Poisoning Attack",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=ARDiscovery(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Spoofed ARP packets",
                        "frequency": "High",
                        "target": "CPS Wi-Fi interface",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description="Inject malicious ARP packets into the ARDiscovery protocol."
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                    "Identify if the firmware has failsafe mechanisms to recover from ARDiscovery Man-in-the-Middle (MiTM) attack.",
                    "Analyze the CPS control logic to assess how malicious ARDiscovery requests impact the CPS movement and operation.",
                    "Create models for the following components: Ground Control Station, Wifi with an ARDisovery protocol, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of an ARDiscovery MiTM attack over Wi-Fi in the CPS model.",
                    "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                    "Check with TA1 to determine the desired impact on control.",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the CPS.",
                    "Identify if the ARDiscovery protocol is used in the networking system.",
                    "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                    "Scan the target Wi-Fi network to identify the CPS's IP and MAC address.",
                    "Craft malicious ARP packets to associate the attacker's MAC address with the CPS's IP address.",
                    "Send the spoofed ARP packets to poison the ARP cache of both the CPS and the controller.",
                    "Capture and analyze the intercepted communication using tools like Wireshark.",
                    "Optionally, inject malicious commands or modify the intercepted data to manipulate CPS behavior.",
            ],

            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as ongoing MitM or successful redirection
        # Example: Check if telemetry data is intercepted
        pass