import os.path
from clorm import Predicate

from saci.modeling.vulnerability import BaseVulnerability
from saci.modeling.device import Device, Wifi, Battery
from saci.modeling.communication import (
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate for battery exhaustion vulnerability logic
class BatteryExhaustionPred(Predicate):
    pass


class BatteryExhaustionVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The vulnerable component is the Battery, affected through Wi-Fi communication
            component=Battery(),
            # Input: Unauthenticated communication from external source causing power drain
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            # Output: Battery exhaustion leading to system shutdown
            output=UnauthenticatedCommunication(),
            # Predicate for reasoning about battery exhaustion vulnerabilities
            attack_ASP=BatteryExhaustionPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "battery_exhaustion_vuln.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[],
        )
        # Human-readable description of the attack input scenario
        self.input = "The CPS's battery will be exhausted as device remains in active mode, leading to DoS"

    def exists(self, device: Device) -> bool:
        # Check if device has both Wi-Fi and Battery components
        has_wifi = False
        has_battery = False
        
        for comp in device.components:
            if isinstance(comp, Wifi):
                has_wifi = True
            elif isinstance(comp, Battery):
                has_battery = True
                
        # Vulnerability exists if device has both Wi-Fi and Battery components
        # and lacks proper power management protection
        return has_wifi and has_battery
