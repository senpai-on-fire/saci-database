import os
from clorm import Predicate, IntegerField

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, TelemetryHigh
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for vulnerabilities in unsecured telemetry systems
class Attack_CPSV_UnsecuredTelemetry(Predicate):
    time = IntegerField()  # Represents the timing aspect of the attack

class UnsecuredTelemetryVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The TelemetryHigh component is vulnerable due to the lack of encryption or authentication
            component=TelemetryHigh(),
            # Input: Unauthenticated communication intercepted or injected by an attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing spoofed or manipulated telemetry data
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about vulnerabilities in unsecured telemetry
            attack_ASP=Attack_CPSV_UnsecuredTelemetry,
            # Logic rules for evaluating vulnerabilities in unsecured telemetry systems
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'unsecured_telemetry.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-311: Missing Encryption of Sensitive Data",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource"
            ],
            attack_vectors_exploits = []

        )
        # Description of the attack scenario
        #self.input = "Intercept and spoof telemetry data due to lack of encryption or authentication."

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is TelemetryHigh and lacks encryption
            if isinstance(comp, TelemetryHigh) and not comp.uses_encryption:
                return True  # Vulnerability exists if TelemetryHigh lacks encryption
        return False  # No vulnerability detected if all TelemetryHigh components use encryption
