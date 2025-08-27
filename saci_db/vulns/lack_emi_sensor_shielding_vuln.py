import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Sensor
from saci.modeling.communication import (
    AuthenticatedCommunication,
    UnauthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for vulnerabilities caused by lack of EMI shielding on sensors
class LackEMISensorShieldingPred(Predicate):
    pass


class LackEMISensorShieldingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Sensor component is vulnerable due to lack of EMI shielding
            component=Sensor(),
            # Input: Authenticated communication simulating EMI signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing corrupted sensor signals or disrupted functionality
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about EMI shielding vulnerabilities in sensors
            attack_ASP=LackEMISensorShieldingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "lack_emi_shielding.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption",
            ],
            attack_vectors=[],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Sensor and lacks proper EMI shielding
            if isinstance(comp, Sensor):
                # Assuming there is an attribute 'has_emi_shielding' indicating if the sensor is shielded
                if not getattr(
                    comp, "has_emi_shielding", False
                ):  # Default to False if the attribute is missing
                    return True  # Vulnerability exists if the sensor lacks shielding
        return False  # No vulnerability detected if all sensors are properly shielded
