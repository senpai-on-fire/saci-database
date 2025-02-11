from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.ardscovery_mitm_vuln import ARDiscoveryMitmVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import Wifi, ARDiscovery, TelemetryHigh, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class ARDiscoveryMitM(CPV):

    NAME = "The ARDiscovery Man-in-the-Middle via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),
                ARDiscovery(),
                TelemetryHigh(),            
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
                "Access to the UAV's network (proximity or Wi-Fi credentials)",
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
                        "target": "UAV Wi-Fi interface",
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
                "Scan the target Wi-Fi network to identify the UAV's IP and MAC address.",
                "Craft malicious ARP packets to associate the attacker's MAC address with the UAV's IP address.",
                "Send the spoofed ARP packets to poison the ARP cache of both the UAV and the controller.",
                "Capture and analyze the intercepted communication using tools like Wireshark.",
                "Optionally, inject malicious commands or modify the intercepted data to manipulate UAV behavior.",
            ],

            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as ongoing MitM or successful redirection
        # Example: Check if telemetry data is intercepted
        pass