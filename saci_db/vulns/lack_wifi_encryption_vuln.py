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
        """
        Checks if the WiFi module lacks authentication mechanisms.
        The vulnerability exists if:
        - The WiFi module supports an **open network** (no password or authentication).
        - The network allows **unauthenticated** connections.
        - The device does not require **mutual authentication** for command transmission.
        """
        for comp in device.components:
            if isinstance(comp, Wifi):
                if comp.encryption_type in [None, "Open"]:
                    return True  # No authentication = vulnerable
                if not comp.requires_mutual_authentication:
                    return True  # No mutual authentication = vulnerable
        return False