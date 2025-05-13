import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, ARDiscovery
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseAttackVector, PacketAttackSignal, BaseCompEffect

# Predicate to define formal reasoning logic for ARDiscovery flooding attacks
class ARDiscoveryFloodPred(Predicate):
    pass

class ARDiscoveryFloodVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The ARDiscovery protocol component is vulnerable to flooding attacks
            component=ARDiscovery(),
            # Input to the flooding attack is unauthenticated communication from an external source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output is network disruption caused by unauthenticated ARDiscovery flood attacks
            output=UnauthenticatedCommunication(),
            # Predicate used for formal reasoning about the ARDiscovery flooding vulnerability
            attack_ASP=ARDiscoveryFloodPred,
            # Logic rules for reasoning about and detecting this vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'ardisovery_flood.lp'),
            # List of associated CWEs
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-406: Insufficient Control of Network Message Volume (Network Amplification)",
                "CWE-661: Improper Handling of Overlapping or Conflicting Actions",
                "CWE-693: Protection Mechanism Failure"
            ],
            attack_vectors_exploits = [
                {
                    "attack_vector": [BaseAttackVector(
                        name="ARDiscovery DoS Flooding Attack",
                        signal=PacketAttackSignal(
                            src=ExternalInput(),
                            dst=ARDiscovery(),
                        ),
                        required_access_level="Proximity",
                        configuration={
                            "target_protocol": "ARDiscovery",
                            "flood_type": "Malformed/Excessive ARDiscovery Requests",
                            "interface_name": "wireless",
                            "attack_args": "--max_requests 1000/sec",
                        },
                    )],
                    "related_cpv": [
                        "ARDiscoveryDoSCPV"
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(category='Availability',
                                       description='Flooding ARDiscovery requests can lead to denial of service, disrupting UAV communication and triggering fail-safe mechanisms.')
                    ],
                    "exploit_steps": [
                        "Prepare the hardware: Ensure you have a Wi-Fi card capable of monitor mode and necessary tools (e.g., Scapy, Wireshark).",
                        "Scan the Wi-Fi network to identify the UAV's SSID using tools like `airodump-ng`.",
                        "Determine the UAV's channel and BSSID via network scanning tools.",
                        "Analyze the ARDiscovery protocol by capturing traffic using Wireshark and saving a sample ARDiscovery connection request packet.",
                        "Craft malicious packets with tools like Scapy to send excessive/malformed ARDiscovery requests to the UAV.",
                        "Flood the UAV with ARDiscovery packets by running a script that sends high-frequency requests.",
                        "Monitor the attack's effectiveness by checking if the UAV loses communication with the controller or enters fail-safe mode.",
                        "Optional: Post-exploitation—use the disruption to perform further analysis or intercept other communications."
                    ],
                    "reference_urls": [
                        "https://ieeexplore.ieee.org/document/7795496"
                    ]
                }
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wifi module
            if isinstance(comp, Wifi):
                # If the Wifi module supports specific protocols, check for ARDiscovery
                if hasattr(comp, 'supported_protocols'):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If ARDiscovery is a supported protocol, the vulnerability exists
                        if isinstance(protocol, ARDiscovery):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching components are found
