import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, Serial
from saci.modeling.communication import AuthenticatedCommunication, UnauthenticatedCommunication, ExternalInput

# Predicate to define formal reasoning logic for vulnerabilities caused by lack of EMI shielding on serial communication lines
class LackEMISerialShieldingPred(Predicate):
    pass

class LackEMISerialShieldingVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Serial component is vulnerable due to the lack of EMI shielding
            component=Serial(),
            # Input: Authenticated communication simulating EMI signals from an external source
            _input=AuthenticatedCommunication(src=ExternalInput()),
            # Output: Authenticated communication representing corrupted serial communication or disrupted functionality
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about EMI shielding vulnerabilities in serial components
            attack_ASP=LackEMISerialShieldingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lack_emi_shielding.lp'),
            # List of Associated CWEs:
            associated_cwe = [
                "CWE-346: Origin Validation Error",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-770: Allocation of Resources Without Limits or Throttling",
                "CWE-400: Uncontrolled Resource Consumption"
            ],
            attack_vectors_exploits = []
        )
    
    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a Serial communication line and lacks EMI shielding
            if isinstance(comp, Serial):
                # Assuming there is an attribute 'has_emi_shielding' to indicate if the serial line is shielded
                if not getattr(comp, 'has_emi_shielding', False):  # Default to False if the attribute is missing
                    return True  # Vulnerability exists if shielding is not present
        return False  # No vulnerability detected if all Serial components are properly shielded
