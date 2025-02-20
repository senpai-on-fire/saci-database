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
        """
        Checks if the WiFi module is vulnerable to deauthentication attacks.
        The vulnerability exists if:
        - The WiFi module does not support Management Frame Protection (MFP).
        - The network is **open** or **uses WPA2 without MFP**.
        - The network allows unprotected disassociation requests.
        """
        for comp in device.components:
            if isinstance(comp, Wifi):
                if comp.encryption_type in [None, "WEP", "Open"]:
                    return True  # Open or weak encryption = vulnerable
                if comp.encryption_type == "WPA2" and not comp.has_management_frame_protection:
                    return True  # WPA2 without MFP = vulnerable
        return False
