import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, AttitudeControlLogic
from saci_db.devices.px4_quadcopter_device import PX4Controller


# Predicate for formal reasoning logic of control loop instability
class ControlLoopInstabilityPred(Predicate):
    pass

class ControlLoopInstabilityVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The Attitude Control Logic module in PX4Controller component vulnerable to control loop instability
            component=AttitudeControlLogic(),
            # Input: Erroneous control logic
            _input=None,
            # Output: Unstable orientation or control loops
            output=None,
            # Predicate for reasoning about this vulnerability
            attack_ASP=ControlLoopInstabilityPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'control_loop_instability.lp'),
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
                # If the controller's attitude control logic is disabled or unstable
                if hasattr(comp, 'attitude_control_stable') and not comp.attitude_control_stable:
                    return True
        return False
