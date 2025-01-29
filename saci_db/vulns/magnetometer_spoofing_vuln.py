import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor import Magnetometer
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for magnetometer spoofing attacks
class MagnetometerSpoofingPred(Predicate):
    pass

class MagnetometerSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The Magnetometer component vulnerable to spoofing attacks
            component=Magnetometer(),
            # Input: Authenticated communication representing spoofed magnetometer signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication leading to erroneous navigation decisions based on spoofed data
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about magnetometer spoofing vulnerabilities
            attack_ASP=MagnetometerSpoofingPred,
            # Logic rules for evaluating magnetometer spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'magnetometer_spoofing.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Magnetometer
            if isinstance(comp, Magnetometer):
                return True  # Vulnerability exists if a magnetometer is found
        return False  # No vulnerability detected if no magnetometer is found
