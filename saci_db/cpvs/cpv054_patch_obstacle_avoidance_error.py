from saci.modeling import CPV
from saci.modeling.device import (
    ObstacleAvoidanceLogic,
    Motor,
    Serial,
)

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.obstacle_avoidance_error_vuln import ObstacleAvoidanceErrorVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln


from saci.modeling.device import Controller

class PatchObstacleAvoidanceErrorCPV(CPV):
    NAME = "The Obstacle Avoidance Failure Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Serial(), # This is the entry component (Required)
                Controller(), # This is the main controller where the firmware is hosted (Required)
                # ObstacleAvoidanceLogic(), # Removed since it's too specific for now (Not Required) 
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[
                PatchMisconfigurationVuln(),
                ObstacleAvoidanceErrorVuln(),
                ControllerIntegrityVuln(),
            ],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Obstacle Avoidance": "Fails to avoid obstacles",
                "Trajectory Calculation": "Inaccurate trajectory leading to collisions",
                "Environment": "Dynamic or hazardous",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "A faulty patch or firmware bug affecting obstacle avoidance calculations.",
                "The vehicle operates in a dynamic environment with potential obstacles or complex navigation.",
                "Simulators",
                "PatchVerif codebase",
            ],
            
            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Obstacle Avoidance Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=ObstacleAvoidanceLogic(),  # Add the binary abstraction here
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
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                    "    - These steps can be performed by revisiting the ArduPilot Git commit history.",
                    "    - Find the version that contains the bugs and inject the code snippet.",
                    "        - If the current version is newer, revert (uncommit) the fixed patch.",
                    "        - If the current version is older, insert the buggy code snippet.",
                    "Derive the triggering condition by running PatchVerif, which provides the triggering unit test input.",
                    "Report the identified triggering condition to TA3 for simulator verification.",
                "TA2 Exploit Steps",
                    "Prepare the simulator for the triggering condition reported by TA2.",
                    "Command the vehicle to operate in a dynamic or obstacle-rich environment.",
                    "Monitor the vehicle’s behavior, focusing on:",
                    "    - Failure to detect or avoid obstacles in its path.",
                    "    - Incorrect navigation leading to direct collisions with objects or the ground.",
                    "Record the physical consequences of crashes, such as:",
                    "    - Damage to the vehicle or surrounding environment.",
                    "    - Loss of operational functionality or control.",
                    "Simulate extended operations to analyze the long-term impact of the patch, including:",
                    "    - Repeated collisions.",
                    "    - Progressive degradation of system performance.",
                    "Refine the attack to target more complex scenarios, including:",
                    "    - Multi-vehicle operations.",
                    "    - Adaptive or mission-critical navigation tasks.",
                "TA3 Exploit Steps",
                    "Use optical imaging tools to catalog all components on the CPS.",
                    "Identify components that contain memory that might store firmware.",
                    "Extract the firmware from the memory component.",
                    "Identify the firmware type and version.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"
            ],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, a crash event or collision detected
        pass
