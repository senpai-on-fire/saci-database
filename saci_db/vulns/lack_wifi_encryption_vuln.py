import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Wifi
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for WiFi vulnerabilities caused by a lack of data integrity or encryption
class LackWifiIntegrityPred(Predicate):
    pass

class LackWifiEncryptionVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Wifi component is vulnerable due to the lack of proper encryption or integrity mechanisms
            component=Wifi(),
            # Input: Unauthenticated communication exploited to inject or alter data
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing altered or compromised WiFi data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about vulnerabilities caused by a lack of WiFi integrity or encryption
            attack_ASP=LackWifiIntegrityPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_wifi_integrity.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-311: Missing Encryption of Sensitive Data",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-326: Inadequate Encryption Strength",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource"
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
                    # Check if any protocol is unauthenticated, indicating a lack of integrity or encryption
                    if issubclass(protocol, UnauthenticatedCommunication):
                        return True  # Vulnerability detected
        return False  # No vulnerability detected if all protocols provide encryption and integrity
