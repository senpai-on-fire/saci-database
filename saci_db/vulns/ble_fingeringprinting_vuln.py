import os.path
from clorm import Predicate

from saci.modeling.vulnerability import PublicSecretVulnerability
from saci.modeling.device import Device
from saci.modeling.device.bluetooth import Bluetooth
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for BLE fingerprinting vulnerabilities
class BLEFingerprintingPred(Predicate):
    pass


class BLEFingeringPrintingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Bluetooth communication stack
            component=Bluetooth(),
            # Input: External BLE advertisement sniffing from an unauthenticated source
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Device fingerprinting information leading to privacy loss
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about BLE fingerprinting vulnerabilities
            attack_ASP=BLEFingerprintingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "ble_fingerprinting.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation",
            ],
            attack_vectors=[],
        )
        # Human-readable description of the attack input scenario
        self.input = "Passive sniffing of BLE advertisement packets to extract static UUIDs for device fingerprinting."

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Bluetooth stack
            if isinstance(comp, Bluetooth): # TODO: and comp.has_static_uuids:
                return True  # Vulnerability exists if device has Bluetooth capability
        return False  # No vulnerability detected if no Bluetooth components found
