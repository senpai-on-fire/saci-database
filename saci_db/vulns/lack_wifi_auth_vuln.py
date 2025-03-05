import os.path
from typing import Iterator
from clorm import Predicate

from saci.modeling.vulnerability import VulnerabilityEffect, MakeEntryEffect, BaseVulnerability
from saci.modeling.device import ComponentID, Device, Wifi
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for vulnerabilities caused by lack of authentication in WiFi communication
class LackWifiAuthenticationPred(Predicate):
    pass

class LackWifiAuthenticationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Wifi component is vulnerable due to a lack of proper authentication mechanisms
            component=Wifi(),
            # Input: Unauthenticated communication exploited by an external attacker
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Unauthenticated communication representing compromised data or unauthorized access
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about the lack of authentication in WiFi communication
            attack_ASP=LackWifiAuthenticationPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_wifi_authentication.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-287: Improper Authentication",
                "CWE-294: Authentication Bypass by Capture-replay",
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-345: Insufficient Verification of Data Authenticity",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-295: Improper Certificate Validation"
            ]
        )

    def _vulnerable_components(self, device: Device) -> Iterator[ComponentID]:
        # Iterate through all components of the device
        for comp_id, comp in device.components.items():
            # Check if the component has supported protocols
            if (supported_protocols := comp.parameters.get("supported_protocols")) is not None:
                # Iterate through the supported protocols
                for protocol in supported_protocols:
                    # Check if any protocol is unauthenticated, indicating a vulnerability
                    if issubclass(protocol, UnauthenticatedCommunication):
                        yield comp_id  # Vulnerability detected

    def exists(self, device: Device) -> bool:
        return any(True for _ in self._vulnerable_components(device))

    def effects(self, device: Device) -> list[VulnerabilityEffect]:
        return [MakeEntryEffect(
            reason="Unauthenticated Wifi",
            nodes=frozenset(self._vulnerable_components(device)),
        )]
