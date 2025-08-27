import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, EmergencyStopLogic
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.device.component.cyber.cyber_abstraction_level import (
    CyberAbstractionLevel,
)
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack
from saci.modeling.attack import BaseCompEffect
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
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "emergency_stop.lp"
            ),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-617: Reachable Assertion",
                "CWE-691: Insufficient Control Flow Management",
                "CWE-856: Missing Commensurate Authentication of Command",
                "CWE-20: Improper Input Validation",
                "CWE-1188: Insecure Default Initialization of Resource",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="Faulty Emergency Stop Patch",
                            signal=BinaryPatchingAttack(
                                src=ExternalInput(),
                                dst=EmergencyStopLogic(),  # Binary abstraction for the emergency stop component
                                modality="binary patch",
                            ),
                            required_access_level="Local or Remote",
                            configuration={
                                "patch_version": "Faulty emergency stop logic"
                            },
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["PatchEmergencyStopFailureCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Availability",
                        description="The faulty patch disables the emergency stop functionality, leading to safety-critical situations where the drone fails to halt during emergencies.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                        "Revisit the ArduPilot Git commit history to identify a version containing the bug.",
                        "Modify the firmware accordingly:",
                        "    - If the current version is newer, revert the fixed patch (uncommit the fix).",
                        "    - If the current version is older, inject the buggy code snippet.",
                        "Derive the triggering condition using PatchVerif, which provides the triggering unit test input.",
                    ],
                    # List of related references
                    "reference_urls": [
                        "https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, PX4Controller):
                # Verify high-level properties of PX4Controller
                if (
                    hasattr(comp, "emergency_stop_enabled")
                    and not comp.emergency_stop_enabled
                ):
                    return True  # Vulnerability detected at a higher abstraction level

                # Check if the PX4Controller has a binary abstraction level
                if CyberAbstractionLevel.BINARY in comp.ABSTRACTIONS:
                    binary_component = comp.ABSTRACTIONS[CyberAbstractionLevel.BINARY]

                    # Verify if the binary abstraction has issues such as patch misconfiguration
                    if hasattr(binary_component, "patch_status"):
                        if binary_component.patch_status in [
                            "outdated",
                            "misconfigured",
                        ]:
                            return True  # Vulnerability detected at the binary level
        return False  # No vulnerability detected
