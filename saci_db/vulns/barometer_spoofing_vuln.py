import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingtVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.barometer import Barometer
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for barometer spoofing attacks
class BarometerSpoofingPred(Predicate):
    pass

class BarometerSpoofingVuln(SpoofingtVulnerability):
    def __init__(self):
        super().__init__(
            # The barometer component vulnerable to spoofing attacks
            component=Barometer(),
            # Input: Spoofed signals injected via authenticated communication from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: authenticated communication representing the result of the spoofed barometer signals
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about barometer spoofing
            attack_ASP=BarometerSpoofingPred,
            # Logic rules for reasoning about the barometer spoofing vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'barometer_spoofing.lp'),
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
            # Check if the component is a barometer
            if isinstance(comp, Barometer):
                return True  # Vulnerability exists if a barometer is found
        return False  # No vulnerability detected if no barometer is found
