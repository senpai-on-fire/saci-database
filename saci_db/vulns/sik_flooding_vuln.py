import os

from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Telemetry, Device, SikRadio
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput


# Predicate to define formal reasoning for SiK radio-based attacks
class SiKFloodingPred(Predicate):
    time = IntegerField()  # Represents the timing aspect of the attack


class SiKFloodingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the SiK radio, which may be used in both TelemetryHigh and TelemetryAlgorithmic systems
            component=SikRadio(),
            # Input: Unauthenticated communication exploited by external attackers
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing the compromised state
            output=UnauthenticatedCommunication(),
            # Predicate for formal reasoning about the SiK radio attack
            attack_ASP=SiKFloodingPred,
            # Logic rules for formal reasoning about vulnerabilities in SiK radios
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'sik.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-311: Missing Encryption of Sensitive Data",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure"
            ]

        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is TelemetryHigh or TelemetryAlgorithmic using the SiK protocol
            if isinstance(comp, (TelemetryHigh, TelemetryAlgorithmic)) and comp.protocol_name == "sik":
                return True  # Vulnerability exists for components using SiK
        return False  # No vulnerability detected
