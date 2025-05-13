import os.path
from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, DSMx
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for DSMx protocol vulnerabilities
class DSMxJammingProtocolPred(Predicate):
    pass


class DSMxJammingProtocolVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the DSMx radio communication stack
            component=DSMx(),
            # Input: Malicious DSMx signal injection from an external, unauthenticated source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Hijacked communication control due to protocol weaknesses
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about DSMx protocol vulnerabilities
            attack_ASP=DSMxJammingProtocolPred,
            # Optional rule file for logic-based reasoning about DSMx protocol weaknesses
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dsmx_jamming_protocol.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-325: Missing Required Cryptographic Step",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-640: Weak Password Recovery Mechanism for Forgotten Password",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-732: Incorrect Permission Assignment for Critical Resource",
            ]
        )
        # Human-readable description of the attack input scenario
        #self.input = (
        #    "Intercepted DSMx protocol communications, brute-forcing the shared secret, "
        #    "and injecting spoofed signals to hijack control of the UAV."
        #)

    def exists(self, device: Device) -> bool:
        """
        Checks if the vulnerability exists in the given device by evaluating whether
        it uses the DSMx protocol and lacks adequate authentication mechanisms.
        """
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a RadioReceiver using the DSMx protocol
            if isinstance(comp, DSMx) and not comp.has_secure_authentication:
                return True  # Vulnerability exists if DSMx lacks secure authentication
        return False  # No vulnerability detected if all RadioReceivers are secure
