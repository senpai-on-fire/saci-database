import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import GNSSReceiver
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for GNSS filtering vulnerabilities
class LackGNSSFilteringPred(Predicate):
    pass

class LackGNSSFilteringVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The GNSSReceiver component is vulnerable due to lack of proper signal filtering
            component=GNSSReceiver(),
            # Input: Unauthenticated GNSS signals from an external source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing corrupted or spoofed GNSS data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about GNSS filtering vulnerabilities
            attack_ASP=LackGNSSFilteringPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_gnss_filtering.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-693: Protection Mechanism Failure"
            ], 
            attack_vectors_exploits = []
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component has supported protocols
            if hasattr(comp, 'supported_protocols'):
                supported_protocols = comp.supported_protocols
                # Iterate through the supported protocols
                for protocol in supported_protocols:
                    # Check if any protocol is unauthenticated, indicating a vulnerability
                    if issubclass(protocol, UnauthenticatedCommunication):
                        return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching conditions are met
