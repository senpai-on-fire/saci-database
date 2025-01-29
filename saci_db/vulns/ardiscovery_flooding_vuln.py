import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi, ARDiscovery
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

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
