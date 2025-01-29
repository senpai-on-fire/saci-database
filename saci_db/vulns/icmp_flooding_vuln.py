import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, ICMP
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for ICMP flood attacks
class IcmpFloodPred(Predicate):
    pass

class IcmpFloodVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The ICMP protocol component that is vulnerable to flooding attacks
            component=ICMP(),
            # Input: Unauthenticated communication used to perform the ICMP flood attack
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Network disruption caused by the unauthenticated ICMP flood
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about ICMP flood vulnerabilities
            attack_ASP=IcmpFloodPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'icmp_flood.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-406: Insufficient Control of Network Message Volume (Network Amplification)",
                "CWE-693: Protection Mechanism Failure",
                "CWE-417: Channel and Path Errors"
            ]

            
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wifi module
            if isinstance(comp, Wifi):
                # If the Wifi module supports specific protocols, check for ICMP
                if hasattr(comp, 'supported_protocols'):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If ICMP is supported, the vulnerability exists
                        if isinstance(protocol, ICMP):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching components are found
