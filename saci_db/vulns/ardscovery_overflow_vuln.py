import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Wifi, Device, ARDiscovery
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseAttackVector, PacketAttackSignal, BaseCompEffect


# Predicate to define formal reasoning logic for ARDiscovery buffer overflow attacks
# Includes a `time` field to represent the timing of the overflow event
class ARDiscoveryOverflowPred(Predicate):
    time = IntegerField()

class ARDiscoveryOverflowVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The ARDiscovery protocol component vulnerable to buffer overflow attacks
            component=ARDiscovery(),
            # Input: Malformed or oversized packets sent from an external, unauthenticated source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Corruption of system memory or operational failure due to buffer overflow
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about the buffer overflow vulnerability
            attack_ASP=ARDiscoveryOverflowPred,
            # Logic rules for evaluating this vulnerability through formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'ardiscovery_overflow.lp'),
            associated_cwe = [
                "CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
                "CWE-125: Out-of-Bounds Read",
                "CWE-787: Out-of-Bounds Write",
                "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
                "CWE-94: Improper Control of Generation of Code ('Code Injection')",
                "CWE-20: Improper Input Validation",
                "CWE-400: Uncontrolled Resource Consumption"
            ],
            attack_vectors_exploits = [
                {
                    "attack_vector": [BaseAttackVector(
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
                    )],
                    "related_cpv": [
                        "ARDiscoveryBufferOverflowCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(category='Availability',
                                       description='Buffer overflow can cause the UAV to crash or exhibit undefined behavior, disrupting operations.')
                    ],
                    "exploit_steps": [
                        "Prepare the hardware and tools: Ensure you have a Wi-Fi card and install required tools like Scapy and Wireshark.",
                        "Capture and analyze ARDiscovery packets using Wireshark to understand the protocol's structure.",
                        "Craft a malicious packet with an oversized payload that exceeds the ARDiscovery protocol's buffer size.",
                        "Use Scapy to send the crafted packet to the UAV over its Wi-Fi network.",
                        "Observe the UAV's behavior to verify a crash or unexpected response, such as rebooting or freezing.",
                        "Optional: Explore if remote code execution is possible by embedding shellcode in the payload."
                    ],
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/document/7795496"
                    ]
                }
            ]
        )
        # Description of the attack input scenario
        self.input = "Overflow the ARDiscovery protocol by sending oversized or malformed packets."

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wifi module
            if isinstance(comp, Wifi):
                # If the Wifi module supports specific protocols, check for ARDiscovery
                if hasattr(comp, 'supported_protocols'):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If ARDiscovery is supported, the vulnerability exists
                        if isinstance(protocol, ARDiscovery):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching components are found
