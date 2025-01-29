import os.path

from clorm import Predicate

from saci.modeling import SpoofingtVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import GPSReceiver
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for GPS spoofing attacks
class GPSSpoofingPred(Predicate):
    pass

class GPSSpoofingVuln(SpoofingtVulnerability):
    def __init__(self):
        super().__init__(
            # The GPSReceiver component vulnerable to spoofing attacks
            component=GPSReceiver(),
            # Input: Unauthenticated GPS signals spoofed by an external source
            _input=UnauthenticatedCommunication(src=ExternalInput),
            # Output: Unauthenticated communication leading to erroneous navigation decisions
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about GPS spoofing vulnerabilities
            attack_ASP=GPSSpoofingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'gps_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource"
            ]

        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a GPSReceiver
            if isinstance(comp, GPSReceiver):
                # Verify if the GPSReceiver supports unauthenticated protocols
                if hasattr(comp, 'supported_protocols'):
                    supported_protocols = comp.supported_protocols
                    for protocol in supported_protocols:
                        # If the protocol is unauthenticated, the vulnerability exists
                        if issubclass(protocol, UnauthenticatedCommunication):
                            return True  # Vulnerability detected
        return False  # No vulnerability detected if no matching conditions are met
