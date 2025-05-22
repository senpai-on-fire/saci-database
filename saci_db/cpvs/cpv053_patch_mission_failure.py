from pathlib import Path
from saci.modeling import CPV

from saci.modeling.device import (
    NavigationControlLogic,
    MultiCopterMotor,
    PWMChannel,
    ESC,
)

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.navigation_control_failure_vuln import NavigationControlFailureVuln
from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class PatchMissionFailureCPV(CPV):
    NAME = "The Mission Failure Due to Faulty Navigation or Control Updates"

    def __init__(self):
        super().__init__(
            required_components=[
                ArduPilotController(),
                NavigationControlLogic(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=ArduPilotController(),
            exit_component=MultiCopterMotor(),
            vulnerabilities=[
                PatchMisconfigurationVuln(),
                NavigationControlFailureVuln(),
                ControllerIntegrityVuln(),
            ],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Mission Status": "Prematurely stopped or failed to complete",
                "Environment": "Dynamic or hazardous environment",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "A faulty patch or update applied to navigation or control logic.",
                "The vehicle is executing a pre-planned mission.",
                "Simulators",
                "PatchVerif codebase",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Navigation or Control Update",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=NavigationControlLogic(),  # Add the binary abstraction here
                        modality="binary patch",
                    ),
                    required_access_level="Local or Remote",
                    configuration={"patch_type": "navigation_update"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Mission Failure",
                    description=(
                        "The faulty patch causes the vehicle to fail its mission due to errors in navigation or control logic, "
                        "leading to premature termination, stalling, or inability to complete its route."
                    ),
                ),
            ],
            exploit_steps=[
                "TA2 Exploit Steps",
                "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                "    - These steps can be performed by revisiting the ArduPilot Git commit history.",
                "    - Find the version that contains the bugs and inject the code snippet.",
                "        - If the current version is newer, revert (uncommit) the fixed patch.",
                "        - If the current version is older, insert the buggy code snippet.",
                "Derive the triggering condition by running PatchVerif, which provides the triggering unit test input.",
                "Report the identified triggering condition to TA3 for simulator verification.",
                "TA1 Exploit Steps",
                "Prepare the simulator for the triggering condition reported by TA2.",
                "Command the vehicle to execute a pre-planned mission.",
                "Monitor the vehicle's performance during the mission, focusing on:",
                "    - Premature stalling or stopping at an unexpected location.",
                "    - Failure to follow the planned route accurately.",
                "    - Erratic behavior in dynamic environments, such as obstacle avoidance failures.",
                "Record the physical and logistical impact of the mission failure, including:",
                "    - Delays in task execution.",
                "    - Safety hazards due to improper navigation.",
                "    - Significant route deviations affecting mission success.",
                "Refine the attack to target broader scenarios, including:",
                "    - Multi-vehicle operations.",
                "    - Dynamic mission replanning environments.",
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
        # For example, mission status is marked as "failure"
        pass
