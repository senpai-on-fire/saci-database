import os.path

from clorm import Predicate

from saci.modeling import SpoofingVulnerability
from saci.modeling.device import PWMChannel, Device
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for PWM spoofing attacks
class PWMSpoofingPred(Predicate):
    pass

class PWMSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The PWMChannel component is vulnerable to spoofing attacks
            component=PWMChannel(),
            # Input: Authenticated communication representing spoofed PWM signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication resulting in erroneous commands sent to the ESC (Electronic Speed Controller)
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about PWM spoofing vulnerabilities
            attack_ASP=PWMSpoofingPred,
            # Logic rules for evaluating PWM spoofing vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'pwm_spoofing.lp'),
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
            # Check if the component is a PWMChannel
            if isinstance(comp, PWMChannel):
                return True  # Vulnerability exists if a PWMChannel is found
        return False  # No vulnerability detected if no PWMChannel is found
