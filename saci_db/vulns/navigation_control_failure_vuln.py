import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, NavigationControlLogic
from saci_db.devices.px4_quadcopter_device import PX4Controller

# Predicate for formal reasoning logic of control logic failure vulnerability
class NavigationControlFailurePred(Predicate):
    pass

class NavigationControlFailureVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to control logic failure
            component=NavigationControlLogic(),
            # Input: Faulty mission planning or control updates
            _input=None,
            # Output: Premature mission termination or failure to complete route
            output=None,
            # Predicate for reasoning about this vulnerability
            attack_ASP=NavigationControlFailurePred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'navigation_control_failure.lp'),
            # List of Associated CWEs
            associated_cwe=[
                "CWE-670: Always-Incorrect Control Flow",
                "CWE-754: Improper Check for Unusual or Exceptional Conditions",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, PX4Controller):
                # If the controller has a control logic error
                if hasattr(comp, 'mission_status') and comp.mission_status == 'failure':
                    return True
        return False
