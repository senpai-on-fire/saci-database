import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, ObstacleAvoidanceLogic
from saci_db.devices.px4_quadcopter_device import PX4Controller

# Predicate for formal reasoning logic of obstacle avoidance error
class ObstacleAvoidanceErrorPred(Predicate):
    pass

class ObstacleAvoidanceErrorVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to obstacle avoidance bugs
            component=ObstacleAvoidanceLogic(),
            # Input: Faulty obstacle avoidance logic
            _input=None,
            # Output: Incorrect navigation leading to crashes
            output=None,
            # Predicate for reasoning about this vulnerability
            attack_ASP=ObstacleAvoidanceErrorPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'avoidance_logic_error.lp'),
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
                # If the controller's obstacle avoidance is inaccurate
                if hasattr(comp, 'obstacle avoidance') and not comp.obstacle_avoidant:
                    return True
        return False
