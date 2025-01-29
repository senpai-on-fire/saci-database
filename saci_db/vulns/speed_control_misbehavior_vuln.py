import os.path
from clorm import Predicate

from saci.modeling.device import Device
from saci.modeling import BaseVulnerability
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci_db.devices.px4_quadcopter_device import PX4Controller


# Predicate to define formal reasoning logic for Emergency Stop vulnerabilities
class SpeedControlMisbehaviorPred(Predicate):
    pass

class SpeedControlMisbehaviorVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to speed misbehavior
            component=PX4Controller(),
            # Input: Malfunctioning speed control logic
            _input=None,
            # Output: Unsafe constant speed during pivot turns
            output=None,
            # Predicate for reasoning about this vulnerability
            attack_ASP=SpeedControlMisbehaviorPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'speed_control_misbehavior.lp'),
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
                # Verify high-level properties of PX4Controller
                if hasattr(comp, 'emergency_stop_enabled') and not comp.emergency_stop_enabled:
                    return True  # Vulnerability detected
                
                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]
                    
                    # Verify if the binary abstraction has issues such as patch misconfiguration
                    if hasattr(binary_component, 'patch_status'):
                        if binary_component.patch_status in ['outdated', 'misconfigured']:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
