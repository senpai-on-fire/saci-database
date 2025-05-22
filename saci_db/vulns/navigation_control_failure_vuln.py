import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.communication import ExternalInput
from saci.modeling.device import Device, NavigationControlLogic
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.attack import BaseCompEffect


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
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "navigation_control_failure.lp",
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
                            name="Faulty Navigation or Control Update",
                            signal=BinaryPatchingAttack(
                                src=ExternalInput(),
                                dst=NavigationControlLogic(),  # Binary abstraction for the navigation control component
                                modality="binary patch",
                            ),
                            required_access_level="Local or Remote",
                            configuration={"patch_type": "navigation_update"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["PatchMissionFailureCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description=(
                            "The faulty patch disrupts the navigation and control logic, causing mission failure through premature termination, stalling, or deviation from planned routes."
                        ),
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        # Steps directly related to deploying and triggering the navigation update fault
                        "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                        "Revisit the ArduPilot Git commit history to find the version containing the bug and inject the code snippet:",
                        "    - If the current version is newer, revert (uncommit) the fixed patch.",
                        "    - If the current version is older, insert the buggy code snippet.",
                        "Derive the triggering condition by running PatchVerif to obtain the necessary unit test input.",
                        # Steps directly related to observing navigation failure
                        "Prepare the simulator for the triggering condition.",
                        "Command the vehicle to execute a pre-planned mission.",
                        "Monitor the vehicle's performance for signs of mission failure, such as premature stalling, inaccurate route following, or erratic behavior during obstacle avoidance.",
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
                # If the controller has a control logic error
                if hasattr(comp, "mission_status") and comp.mission_status == "failure":
                    return True
        return False
