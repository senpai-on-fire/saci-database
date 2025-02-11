from pathlib import Path
from saci.modeling import CPV
from saci.modeling.device import ObstacleAvoidanceLogic, MultiCopterMotor, PWMChannel, ESC

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.obstacle_avoidance_error_vuln import ObstacleAvoidanceErrorVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class PatchObstacleAvoidanceErrorCPV(CPV):

    NAME = "The Obstacle Avoidance Failure Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                ObstacleAvoidanceLogic(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=ObstacleAvoidanceLogic(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[PatchMisconfigurationVuln(), ObstacleAvoidanceErrorVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Obstacle Avoidance": "Fails to avoid obstacles",
                "Trajectory Calculation": "Inaccurate trajectory leading to collisions",
                "Environment": "Dynamic or hazardous",
                "RemoteController": "Active",
                "CPSController": "Active",
                "Operating mode": "Any",
            },
            attack_requirements=[
                "A faulty patch or firmware bug affecting obstacle avoidance calculations.",
                "The vehicle operates in a dynamic environment with potential obstacles or complex navigation.",
                "Simulators",
                "PatchVerif codebase"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Obstacle Avoidance Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=ObstacleAvoidanceLogic(), # Add the binary abstraction here
                        modality="binary patch",
                    ),
                    required_access_level="Local or Remote",
                    configuration={"patch_type": "obstacle_avoidance"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Crash-Inducing Behavior",
                    description=(
                        "The faulty patch causes the vehicle to fail in obstacle avoidance, "
                        "resulting in direct collisions with objects or the ground, causing damage to the vehicle and its surroundings."
                    ),
                ),
            ],
            exploit_steps = {
                "TA3 Exploit Steps": [
                    "Use Optical imaging tools to catalog all of the components on the rover.",
                    "Identify which components contained memory that might contain firmware."
                ],
                "TA2 Exploit Steps": [
                    "Extract the firmware from the memory component.",
                    "Identify the firmware type and version.",
                    "Deploy the faulty patch onto the drone's flight controller, either through direct access or remote update mechanisms.",
                    "   - These steps can be done by revisiting the ArduPilot git commit history.",
                    "   - Find the version that has these bugs and inject the code snippet.",
                    "       - If the current version is newer, uncommit the fixed patch.",
                    "       - If the current version is older, add the code snippet.",
                    "Derive the triggering condition by running PatchVerif, which gives the triggering unit test input.",
                    "Report the triggering condition to TA3 for simulator verification."
                ],
                "TA1 Exploit Steps": [
                    "Prepare the simulator for the triggering condition reported by TA2.",
                    "Command the vehicle to operate in a dynamic or obstacle-rich environment.",
                    "Monitor the vehicle's behavior, including:",
                    "   - Failure to detect or avoid obstacles in its path.",
                    "   - Incorrect navigation causing direct collisions with objects or the ground.",
                    "Record the physical consequences of crashes, such as damage to the vehicle or surrounding environment.",
                    "Simulate extended operations to analyze the long-term impact of the patch, such as repeated collisions or degradation of system performance.",
                    "Refine the attack to target more complex scenarios or multi-vehicle operations."
                ]
            },
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, a crash event or collision detected
        pass
