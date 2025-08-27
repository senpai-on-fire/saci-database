import os.path
from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.device import Device, ObstacleAvoidanceLogic
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack
from saci.modeling.attack import BaseCompEffect


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
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "avoidance_logic_error.lp"
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
                    "attack_vector": [
                        BaseAttackVector(
                            name="Faulty Obstacle Avoidance Patch",
                            signal=BinaryPatchingAttack(
                                src=ExternalInput(),
                                dst=ObstacleAvoidanceLogic(),  # Binary abstraction for the obstacle avoidance component
                                modality="binary patch",
                            ),
                            required_access_level="Local or Remote",
                            configuration={"patch_type": "obstacle_avoidance"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["PatchObstacleAvoidanceErrorCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description=(
                            "The faulty patch causes the vehicle to fail in obstacle avoidance, resulting in direct collisions with objects or the ground, "
                            "which can damage the vehicle and its surroundings."
                        ),
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        # Steps directly related to patch deployment and triggering on the obstacle avoidance component
                        "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                        "Revisit the ArduPilot Git commit history to find the version containing the bug and inject the code snippet:",
                        "    - If the current version is newer, revert (uncommit) the fixed patch.",
                        "    - If the current version is older, insert the buggy code snippet.",
                        "Derive the triggering condition by running PatchVerif to obtain the necessary unit test input.",
                        # Steps directly related to observing obstacle avoidance failure
                        "Prepare the simulator for the triggering condition.",
                        "Command the vehicle to operate in a dynamic or obstacle-rich environment.",
                        "Monitor the vehicle’s behavior for failure to detect or avoid obstacles, leading to direct collisions.",
                        "Record the physical consequences of crashes, including damage to the vehicle and its surroundings.",
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
                # If the controller's obstacle avoidance is inaccurate
                if hasattr(comp, "obstacle avoidance") and not comp.obstacle_avoidant:
                    return True
        return False
