import os.path

from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, Wifi
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)


class LackBeaconFilteringPred(Predicate):
    pass


class LackBeaconFilteringVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Wi-Fi stack
            component=Wifi(),
            # Input: Flood of beacon frames from an unauthenticated external source
            _input=UnauthenticatedCommunication(),
            # Output: Overwhelmed communication stack leading to denial of service
            output=UnauthenticatedCommunication(),
            # No specific attack predicate is defined for this vulnerability
            attack_ASP=LackBeaconFilteringPred,
            # Optional rule file for formal logic (if needed)
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "lack_beacon_filtering.lp"
            ),
            # List of Associated CWEs:
            # List of Associated CWEs
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-693: Protection Mechanism Failure",
                "CWE-916: Use of an Insecure Protocol",
            ],
            attack_vectors=[],
        )
        self.input = "Flood of malicious beacon frames targeting the UAV's Wi-Fi communication stack."

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            # Check if the component is Wi-Fi and lacks beacon filtering
            if isinstance(comp, Wifi) and not comp.has_beacon_filtering:
                return True
        return False
