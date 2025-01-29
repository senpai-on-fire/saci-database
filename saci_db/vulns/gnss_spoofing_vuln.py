import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import GNSSReceiver
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for GNSS spoofing attacks
class GNSSSpoofingPred(Predicate):
    pass

class GNSSSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The GNSSReceiver component vulnerable to spoofing attacks
            component=GNSSReceiver(),
            # Input: Unauthenticated GNSS signals spoofed by an external source
            _input=UnauthenticatedCommunication(src=ExternalInput),
            # Output: Unauthenticated communication leading to erroneous navigation decisions
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about GNSS spoofing vulnerabilities
            attack_ASP=GNSSSpoofingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gnss_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-354: Improper Validation of Integrity Check Value"
            ]

        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a GNSSReceiver
            if isinstance(comp, GNSSReceiver):
                # Verify if the GNSSReceiver supports unauthenticated protocols
                if hasattr(comp, 'supported_protocols'):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If the protocol is unauthenticated, the vulnerability exists
                        if issubclass(protocol, UnauthenticatedCommunication):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching conditions are met