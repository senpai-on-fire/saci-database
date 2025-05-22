import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, ARDiscovery
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)
from saci.modeling.attack import BaseAttackVector, PacketAttackSignal, BaseCompEffect


# Predicate to define formal reasoning for an ARDiscovery Man-in-the-Middle (MITM) attack
# Includes a time field to model the timing of the attack
class ARDiscoveryMitmPred(Predicate):
    time = IntegerField()


class ARDiscoveryMitmVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The ARDiscovery protocol component vulnerable to MITM attacks
            component=ARDiscovery(),
            # Input: Unauthenticated communication simulating ARP cache poisoning
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthorized access achieved through the MITM attack
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about ARDiscovery MITM attacks
            attack_ASP=ARDiscoveryMitmPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "ardiscovery_mitm.lp"
            ),
            # List of associated CWEs
            associated_cwe=[
                "CWE-300: Channel Accessible by Non-Endpoint ('Man-in-the-Middle')",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-441: Unintended Proxy or Intermediary ('Confused Deputy')",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-693: Protection Mechanism Failure",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
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
                    "related_cpv": ["ARDiscoveryMitM"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="ARP cache poisoning can lead to unauthorized interception and manipulation of UAV communication.",
                        )
                    ],
                    "exploit_steps": [
                        "Scan the target Wi-Fi network to identify the UAV's IP and MAC address.",
                        "Craft malicious ARP packets to associate the attacker's MAC address with the UAV's IP address.",
                        "Send the spoofed ARP packets to poison the ARP cache of both the UAV and the controller.",
                        "Capture and analyze the intercepted communication using tools like Wireshark.",
                        "Optionally, inject malicious commands or modify the intercepted data to manipulate UAV behavior.",
                    ],
                    "reference_urls": ["https://ieeexplore.ieee.org/document/7795496"],
                }
            ],
        )
        # Description of the input attack scenario
        self.input = "launch a ARDiscovery Protocol MITM attack"

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wifi module
            if isinstance(comp, Wifi):
                # Verify if the Wifi module supports specific protocols
                if hasattr(comp, "supported_protocols"):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If ARDiscovery is supported, the vulnerability exists
                        if isinstance(protocol, ARDiscovery):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching components are found
