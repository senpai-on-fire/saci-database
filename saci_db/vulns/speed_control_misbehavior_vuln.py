import os.path
from clorm import Predicate

from saci.modeling.device import Device, SpeedControlLogic
from saci.modeling import BaseVulnerability
from saci.modeling.communication import ExternalInput
from saci.modeling.device.component.cyber.cyber_abstraction_level import (
    CyberAbstractionLevel,
)
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack import BaseCompEffect
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack
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
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "speed_control_misbehavior.lp",
            ),
            # List of Associated CWEs
            associated_cwe=[
                "CWE-670: Always-Incorrect Control Flow",
                "CWE-754: Improper Check for Unusual or Exceptional Conditions",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="Faulty Speed Control Patch",
                            signal=BinaryPatchingAttack(
                                src=ExternalInput(),
                                dst=SpeedControlLogic(),  # Binary abstraction for the speed control component
                                modality="binary patch",
                            ),
                            required_access_level="Local or Remote",
                            configuration={"patch_type": "pivot_turn_speed_control"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["PatchPivotTurnMalfunctionCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description=(
                            "The faulty patch causes the vehicle to maintain an unsafe constant speed during pivot turns, "
                            "increasing the risk of rollovers or loss of stability."
                        ),
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                        "Revisit the ArduPilot Git commit history to find the version containing the bug and inject the code snippet:",
                        "    - If the current version is newer, revert (uncommit) the fixed patch.",
                        "    - If the current version is older, insert the buggy code snippet.",
                        "Derive the triggering condition by running PatchVerif, which provides the triggering unit test input.",
                    ],
                    # List of related references
                    "reference_urls": ["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a PX4Controller
            if isinstance(comp, PX4Controller):
                # Verify high-level properties of PX4Controller
                if hasattr(comp, "emergency_stop_enabled") and not comp.emergency_stop_enabled:
                    return True  # Vulnerability detected

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
