import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Telnet
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate for Telnet vulnerability logic
class OpenTelnetPred(Predicate):
    pass

class OpenTelnetVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # Telnet is vulnerable due to open, unauthenticated access
            component=Telnet(),
            # Input: Unauthenticated communication exploited by an external attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthorized system control or data leakage
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about open Telnet vulnerabilities
            attack_ASP=OpenTelnetPred,
            # Logic rules for evaluating this vulnerability
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'open_telnet_vuln.lp'),
            # Associated CWEs
            associated_cwe=[
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-287: Improper Authentication",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-732: Incorrect Permission Assignment for Critical Resource",
                "CWE-284: Improper Access Control"
            ],
            attack_vectors_exploits = []
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, Telnet):
                return True  # Vulnerability exists if TelnetService is found
        return False