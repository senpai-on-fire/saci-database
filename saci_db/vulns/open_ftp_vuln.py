import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, FTP
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate for FTP vulnerability logic
class OpenFTPPred(Predicate):
    pass


class OpenFTPVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # FTP is vulnerable due to open access without authentication
            component=FTP(),
            # Input: Unauthenticated communication exploited by an external attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthorized access to files or data leakage
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about open FTP vulnerabilities
            attack_ASP=OpenFTPPred,
            # Logic rules for evaluating this vulnerability
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "open_ftp_vuln.lp"
            ),
            # Associated CWEs
            associated_cwe=[
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-287: Improper Authentication",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-538: File and Directory Information Exposure",
                "CWE-732: Incorrect Permission Assignment for Critical Resource",
                "CWE-284: Improper Access Control",
            ],
            attack_vectors=[],
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, FTP):
                return True  # Vulnerability exists if FTPService is found
        return False
