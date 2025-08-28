import os.path

from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device, WebServer
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for vulnerabilities caused by weak application authentication
class WeakApplicationAuthPred(Predicate):
    pass


class WeakApplicationAuthVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The WebServer component is vulnerable due to weak or missing authentication mechanisms
            component=WebServer(),
            # Input: Unauthenticated HTTP GET requests exploited by attackers
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication indicating unauthorized access or data exposure
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about weak application authentication vulnerabilities
            attack_ASP=WeakApplicationAuthPred,
            # Logic rules for evaluating vulnerabilities in weak application authentication
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "weak_application_auth.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-287: Improper Authentication",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-522: Insufficiently Protected Credentials",
                "CWE-319: Cleartext Transmission of Sensitive Information",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-295: Improper Certificate Validation",
            ],
            attack_vectors=[],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a WebServer and uses the HTTP protocol without authentication
            if isinstance(comp, WebServer) and comp.protocol_name == "http":
                # Further checks can be added here to refine the vulnerability detection
                # For example, check if authentication headers or TLS/SSL is enabled
                if not comp.has_tls and not comp.requires_authentication:
                    return True  # Vulnerability exists if no TLS or authentication is enforced
        return False  # No vulnerability detected if all WebServers are secured
