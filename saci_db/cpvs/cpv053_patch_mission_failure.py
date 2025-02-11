from pathlib import Path
from saci.modeling import CPV

from saci.modeling.device import NavigationControlLogic, MultiCopterMotor, PWMChannel, ESC

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.navigation_control_failure_vuln import NavigationControlFailureVuln
from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class PatchMissionFailureCPV(CPV):
    
    NAME = "The Mission Failure Due to Faulty Navigation or Control Updates"

    def __init__(self):
        super().__init__(
            required_components=[
                NavigationControlLogic(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=NavigationControlLogic(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[PatchMisconfigurationVuln(), NavigationControlFailureVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Mission Status": "Prematurely stopped or failed to complete",
                "Environment": "Dynamic or hazardous environment",
                "RemoteController": "Active",
                "CPSController": "Active",
                "Operating mode": "Any",
            },
            attack_requirements=[
                "A faulty patch or update applied to navigation or control logic.",
                "The vehicle is executing a pre-planned mission.",
                "Simulators",
                "PatchVerif codebase"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Navigation or Control Update",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=NavigationControlLogic(), # Add the binary abstraction here
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
                    "Command the vehicle to execute a pre-planned mission.",
                    "Monitor the vehicle's performance during the mission, including:",
                    "   - Premature stalling or stopping at an unexpected point.",
                    "   - Failure to follow the planned route accurately.",
                    "   - Erratic behavior in dynamic environments such as obstacle avoidance failure.",
                    "Record the physical and logistical impact of the mission failure, including delays, safety hazards, and route deviation.",
                    "Refine the attack to target broader scenarios, including multi-vehicle operations or dynamic mission replanning environments."
                ]
            },
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, mission status is marked as "failure"
        pass
