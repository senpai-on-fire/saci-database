import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Wifi, Device, ARDiscovery
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

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
                "CWE-400: Uncontrolled Resource Consumption"]
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
