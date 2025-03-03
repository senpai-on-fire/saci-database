import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.compass import CompassSensor
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for compass spoofing attacks
class CompassSpoofingPred(Predicate):
    pass

class CompassSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The CompassSensor component vulnerable to spoofing attacks
            component=CompassSensor(),
            # Input: Authenticated communication representing spoofed signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing erroneous navigation decisions caused by spoofed compass data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about compass spoofing
            attack_ASP=CompassSpoofingPred,
            # Logic rules for evaluating the compass spoofing vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'compass_spoofing.lp'),
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
            # Check if the component is a CompassSensor
            if isinstance(comp, CompassSensor):
                return True  # Vulnerability exists if a CompassSensor is found
        return False  # No vulnerability detected if no CompassSensor is found
