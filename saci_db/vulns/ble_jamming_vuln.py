import os.path
from clorm import Predicate

from saci.modeling.vulnerability import PublicSecretVulnerability
from saci.modeling.device import Device
from saci.modeling.device.bluetooth import Bluetooth
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for BLE jamming vulnerabilities
class BLEJammingPred(Predicate):
    pass


class BLEJammingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Bluetooth communication stack
            component=Bluetooth(),
            # Input: External RF interference from an unauthenticated, malicious source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Disrupted BLE communication leading to loss of connectivity
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about BLE jamming vulnerabilities
            attack_ASP=BLEJammingPred,
            # Optional rule file for logic-based reasoning about BLE jamming
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "ble_jamming.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
            ],
            attack_vectors=[],
        )
        # Human-readable description of the attack input scenario
        self.input = "Deliberate RF interference targeting BLE advertising channels (37-39) at 2.4 GHz."

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Bluetooth stack and lacks RF interference protection
            if isinstance(comp, Bluetooth) and not comp.has_rf_protection:
                return True  # Vulnerability exists if Bluetooth lacks RF protection
        return False  # No vulnerability detected if all Bluetooth stacks have RF protection
