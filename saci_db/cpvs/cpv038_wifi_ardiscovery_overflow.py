from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.ardscovery_overflow_vuln import ARDiscoveryOverflowVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import  Wifi, TelemetryHigh, ARDiscovery, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class ARDiscoveryBufferOverflowCPV(CPV):

    NAME = "The ARDiscovery Buffer Overflow via Wifi"

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

            vulnerabilities=[LackWifiAuthenticationVuln(), LackWifiEncryptionVuln(), ARDiscoveryOverflowVuln()],

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
                "Wireshark or equivalent traffic analysis tool",
                "Scapy or other packet crafting libraries",
                "Basic understanding of the ARDiscovery protocol structure",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="ARDiscovery Buffer Overflow Attack",
                    signal=PacketAttackSignal(
                        src=ExternalInput(),
                        dst=ARDiscovery(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "target_protocol": "ARDiscovery",
                        "packet_size": "Exceeds buffer limit",
                        "interface_name": "wireless",
                        "attack_args": "Oversized payload with malicious data",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Causes the CPS to crash or exhibit undefined behavior, disrupting operations."
                ),
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Get the extracted CPS firmware from TA3.",
                    "Check if the CPS uses an ARDiscovery protocol over WiFi",
                    "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms",
                
                "TA2 Exploit Steps",
                    "Implement a simulation of an ARDiscovery flooding attack over Wi-Fi in the CPS model.",
                    "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                    "Check with TA1 to determine the desired impact on control.",

                "TA3 Exploit Steps",
                    "Prepare the hardware and tools: Ensure you have a Wi-Fi card and install required tools like Scapy and Wireshark.",
                    "Capture and analyze ARDiscovery packets using Wireshark to understand the protocol's structure.",
                    "Craft a malicious packet with an oversized payload that exceeds the ARDiscovery protocol's buffer size.",
                    "Use Scapy to send the crafted packet to the CPS over its Wi-Fi network.",
                    "Observe the CPS's behavior to verify a crash or unexpected response, such as rebooting or freezing.",
                    "Optional: Explore if remote code execution is possible by embedding shellcode in the payload."
            ],

            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO: Define the specific goal state conditions (e.g., CPS in crashed or unresponsive state)
        pass
