import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for RF interference vulnerabilities
class RFInterferencePred(Predicate):
    pass


class RFInterferenceVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Wi-Fi communication stack
            component=Wifi(),
            # Input: External RF interference from an unauthenticated, malicious source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Disrupted communication leading to loss of control and telemetry
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about RF interference vulnerabilities
            attack_ASP=RFInterferencePred,
            # Optional rule file for logic-based reasoning about RF interference
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "rf_interference.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-693: Protection Mechanism Failure",
                "CWE-661: Improper Handling of Overlapping or Conflicting Actions",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors_exploits=[],
        )
        # Human-readable description of the attack input scenario
        self.input = (
            "Deliberate RF interference targeting the UAV's communication frequencies."
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Wi-Fi stack and lacks RF interference protection
            if isinstance(comp, Wifi) and not comp.has_rf_protection:
                return True  # Vulnerability exists if Wi-Fi lacks RF protection
        return False  # No vulnerability detected if all Wi-Fi stacks have RF protection
