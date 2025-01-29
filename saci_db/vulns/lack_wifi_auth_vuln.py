import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Wifi
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for vulnerabilities caused by lack of authentication in WiFi communication
class LackWifiAuthenticationPred(Predicate):
    pass

class LackWifiAuthenticationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Wifi component is vulnerable due to a lack of proper authentication mechanisms
            component=Wifi(),
            # Input: Unauthenticated communication exploited by an external attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing compromised data or unauthorized access
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about the lack of authentication in WiFi communication
            attack_ASP=LackWifiAuthenticationPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_wifi_authentication.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-295: Improper Certificate Validation"
            ]
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
        return False  # No vulnerability detected if all protocols are authenticated
