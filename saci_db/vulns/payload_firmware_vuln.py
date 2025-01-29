import os.path
from clorm import Predicate

from saci.modeling.device import Device
from saci.modeling import BaseVulnerability
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel

from saci_db.devices.propriety_quadcopter_device import ProprietyQuadcopter

# Predicate to define formal reasoning logic for firmware vulnerabilities
class FirmwareVulnerabilityPred(Predicate):
    pass

class FirmwarePayloadVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            # The PX4Controller component vulnerable to firmware exploits
            component=ProprietyQuadcopter(),
            # Input: Firmware-related issues (e.g., outdated, unverified, or insecure firmware)
            _input=None,
            # Output: Exploited firmware leading to UAV compromise
            output=None,
            # Predicate for reasoning about firmware vulnerabilities
            attack_ASP=FirmwareVulnerabilityPred,
            # Logic rules for evaluating firmware vulnerabilities in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'firmware_payload_vuln.lp'),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-306: Missing Authentication for Critical Function",
                "CWE-494: Download of Code Without Integrity Check",
                "CWE-295: Improper Certificate Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation"
            ]
        )

    def exists(self, device: Device) -> bool:
        """
        Checks if the firmware vulnerability exists in the given device by evaluating its firmware configuration.
        """
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, ProprietyQuadcopter):
                # Verify high-level properties of the PX4Controller for firmware configuration
                if hasattr(comp, 'firmware_status') and comp.firmware_status in ['outdated', 'unverified']:
                    return True  # Vulnerability detected at the high level
                
                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]
                    
                    # Verify if the binary abstraction has firmware issues
                    if hasattr(binary_component, 'integrity_status'):
                        if binary_component.integrity_status in ['corrupted', 'tampered']:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
