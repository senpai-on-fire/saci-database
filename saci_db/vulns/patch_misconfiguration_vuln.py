import os.path
from clorm import Predicate

from saci.modeling.device import Device
from saci.modeling import BaseVulnerability
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci_db.devices.px4_quadcopter_device import PX4Controller

# Predicate to define formal reasoning logic for patch misconfiguration vulnerabilities
class PatchMisconfigurationPred(Predicate):
    pass

class PatchMisconfigurationVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to misconfigured patches
            component=PX4Controller(),
            # Input: Patch misconfiguration
            _input=None,
            # Output: Malicious Patch configuration in the firmware
            output=None,
            # Predicate for reasoning about patch misconfiguration vulnerabilities
            attack_ASP=PatchMisconfigurationPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'patch_misconfiguration.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-912: Hidden Functionality",
                "CWE-672: Operation on a Resource after Expiration or Release",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource"
            ]
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, PX4Controller):
                # Verify high-level properties of PX4Controller for patch configuration
                if hasattr(comp, 'patch_configured') and not comp.patch_configured:
                    return True  # Vulnerability detected at a higher abstraction level
                
                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]
                    
                    # Verify if the binary abstraction has issues such as patch misconfiguration
                    if hasattr(binary_component, 'patch_status'):
                        if binary_component.patch_status in ['outdated', 'misconfigured']:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
