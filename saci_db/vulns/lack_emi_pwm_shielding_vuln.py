import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, PWMChannel
from saci.modeling.communication import (
    AuthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for vulnerabilities caused by lack of EMI shielding on PWM channels
class LackEMIPWMShieldingPred(Predicate):
    pass


class LackEMIPWMShieldingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PWMChannel component is vulnerable due to the lack of EMI shielding
            component=PWMChannel(),
            # Input: Authenticated communication simulating EMI signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing corrupted PWM signals or disrupted functionality
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about EMI shielding vulnerabilities
            attack_ASP=LackEMIPWMShieldingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "lack_emi_shielding.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-94: Improper Control of Generation of Code ('Code Injection')",
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
            # Check if the component is a PWMChannel and lacks proper EMI shielding
            if isinstance(comp, PWMChannel):
                # Assuming there is an attribute 'has_emi_shielding' to indicate if the channel is shielded
                if not getattr(
                    comp, "has_emi_shielding", False
                ):  # Default to False if the attribute is missing
                    return True  # Vulnerability exists if shielding is not present
        return False  # No vulnerability detected if all PWM channels are shielded
