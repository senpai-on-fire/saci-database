import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.device import Device, AttitudeControlLogic
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import BaseCompEffect


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
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "control_loop_instability.lp",
            ),
            # List of Associated CWEs
            associated_cwe=[
                "CWE-670: Always-Incorrect Control Flow",
                "CWE-754: Improper Check for Unusual or Exceptional Conditions",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-20: Improper Input Validation",
            ],
            attack_vectors_exploits=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Faulty Attitude Control Patch",
                            signal=BinaryPatchingAttack(
                                src=ExternalInput(),
                                dst=AttitudeControlLogic(),  # Binary abstraction for the attitude control component
                                modality="binary patch",
                            ),
                            required_access_level="Local or Remote",
                            configuration={"patch_type": "attitude_control"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["PatchUnstableAttitudeControlCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description=(
                            "The faulty patch causes the vehicle to exhibit erratic and unstable attitude control, "
                            "leading to unexpected tilting, erratic movement, or crashes."
                        ),
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                        "    - These steps can be performed by revisiting the ArduPilot Git commit history.",
                        "    - Find the version that contains the bugs and inject the code snippet.",
                        "        - If the current version is newer, revert (uncommit) the fixed patch.",
                        "        - If the current version is older, insert the buggy code snippet.",
                        "Derive the triggering condition by running PatchVerif, which provides the triggering unit test input.",
                        "Report the identified triggering condition to TA3 for simulator verification.",
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
                # If the controller's attitude control logic is disabled or unstable
                if (
                    hasattr(comp, "attitude_control_stable")
                    and not comp.attitude_control_stable
                ):
                    return True
        return False
