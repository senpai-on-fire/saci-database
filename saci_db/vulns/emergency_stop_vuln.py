import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci_db.devices.px4_quadcopter_device import PX4Controller

# Predicate to define formal reasoning logic for Emergency Stop vulnerabilities
class EmergencyStopPred(Predicate):
    pass

class EmergencyStopVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to Emergency Stop logic failures
            component=PX4Controller(),
            # Input: Malfunctioning Emergency Stop logic failures
            _input=None,
            # Output: Fault Emergency Stop logic commands
            output=None,
            # Predicate for reasoning about Emergency Stop vulnerabilities
            attack_ASP=EmergencyStopPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'emergency_stop.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-617: Reachable Assertion",
                "CWE-691: Insufficient Control Flow Management",
                "CWE-856: Missing Commensurate Authentication of Command",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, PX4Controller):
                # Verify high-level properties of PX4Controller
                if hasattr(comp, 'emergency_stop_enabled') and not comp.emergency_stop_enabled:
                    return True  # Vulnerability detected at a higher abstraction level
                
                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]
                    
                    # Verify if the binary abstraction has issues such as patch misconfiguration
                    if hasattr(binary_component, 'patch_status'):
                        if binary_component.patch_status in ['outdated', 'misconfigured']:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
