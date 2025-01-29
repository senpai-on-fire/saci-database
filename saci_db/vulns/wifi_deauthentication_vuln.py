import os.path

from clorm import Predicate

'''
Modeling the deauthentication attack described in the research article:
https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8658279

Actual impacts:
- The CX-10W drone fell out of the sky.
- The Parrot AR drone performed an emergency landing procedure.

Modeled impact:
- Emergency landing procedure triggered after WiFi disconnection.
'''

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device
from saci.modeling.device import CyberComponentBase, Wifi
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for WiFi deauthentication attacks
class WiFiDeauthPred(Predicate):
    pass

class WiFiDeauthVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the WiFi module
            component=Wifi(),
            # Input: Unauthenticated communication exploited to send deauthentication frames
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication leading to disconnection from the network
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about WiFi deauthentication attacks
            attack_ASP=WiFiDeauthPred,
            # Logic rules for evaluating vulnerabilities to deauthentication attacks
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'wifi_deauth.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-287: Improper Authentication",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-693: Protection Mechanism Failure"
            ]     
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a WiFi module
            if isinstance(comp, Wifi):
                # Check if the WiFi module uses WPA2 encryption without management frame protection
                if comp.encryption_type == "WPA2" and not comp.has_management_frame_protection:
                    return True  # Vulnerability exists due to lack of management frame protection
                # Check if the WiFi module has no encryption, making it vulnerable by default
                if comp.encryption_type is None:
                    return True  # Vulnerability exists due to lack of encryption
        return False  # No vulnerability detected if all conditions are unmet
