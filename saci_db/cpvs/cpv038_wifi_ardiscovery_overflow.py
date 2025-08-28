from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from saci_db.vulns.lack_wifi_encryption_vuln import LackWifiEncryptionVuln
from saci_db.vulns.ardscovery_overflow_vuln import ARDiscoveryOverflowVuln

from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import (
    Wifi,
    ARDiscovery,
    Motor,
)
from saci.modeling.state import GlobalState

from saci.modeling.device import Controller


class ARDiscoveryBufferOverflowCPV(CPV):
    NAME = "The ARDiscovery Buffer Overflow via Wifi"

    def __init__(self):
        super().__init__(
            required_components=[
                Wifi(),  # This is the entry component (Required)
                ARDiscovery(),  # ARDiscovery is a required vulnerable component (Required)
                Controller(),  # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Wifi(),
            exit_component=Motor(),
            vulnerabilities=[
                LackWifiAuthenticationVuln(),
                LackWifiEncryptionVuln(),
                ARDiscoveryOverflowVuln(),
            ],
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
                    description="Causes the CPS to crash or exhibit undefined behavior, disrupting operations.",
                ),
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the CPS firmware to determine if the Wi-Fi implements security mechanisms such as Management Frame Protection (MFP).",
                "Identify if the firmware has failsafe mechanisms to recover from ARDiscovery overflow attack.",
                "Analyze the CPS control logic to assess how very long ARDiscovery requests impact the CPS movement and operation.",
                "Create models for the following components: Ground Control Station, Wifi with an ARDisovery protocol, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                "Report to TA2 any required physical parameters to simulate the CPS dynamics",
                "TA2 Exploit Steps",
                "Implement a simulation of an ARDiscovery overflow attack over Wi-Fi in the CPS model.",
                "Run the simulation to analyze how loss of communication translates to control failure in the CPS device.",
                "Check with TA1 to determine the desired impact on control.",
                "Report the findings to TA3 to conduct the experiments on the physical CPS device",
                "TA3 Exploit Steps",
                "Use imaging tools and other techniques to catalog all Wi-Fi-related hardware components on the CPS.",
                "Identify if the ARDiscovery protocol is used in the networking system.",
                "Identify the specific Wi-Fi module and extract the Wi-Fi SSID and password.",
                "Prepare the hardware and tools: Ensure you have a Wi-Fi card and install required tools like Scapy and Wireshark.",
                "Capture and analyze ARDiscovery packets using Wireshark to understand the protocol's structure.",
                "Craft a malicious packet with an oversized payload that exceeds the ARDiscovery protocol's buffer size.",
                "Use Scapy to send the crafted packet to the CPS over its Wi-Fi network.",
                "Observe the CPS's behavior to verify a crash or unexpected response, such as rebooting or freezing.",
                "Optional: Explore if remote code execution is possible by embedding shellcode in the payload.",
            ],
            associated_files=[],
            reference_urls=["https://ieeexplore.ieee.org/document/7795496"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO: Define the specific goal state conditions (e.g., CPS in crashed or unresponsive state)
        pass
