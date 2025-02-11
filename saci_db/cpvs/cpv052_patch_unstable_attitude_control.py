from pathlib import Path
from saci.modeling import CPV
from saci.modeling.device import AttitudeControlLogic, MultiCopterMotor, PWMChannel, ESC

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.control_loop_instability_vuln import ControlLoopInstabilityVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class PatchUnstableAttitudeControlCPV(CPV):
    
    NAME = "The Unstable Attitude Control Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                AttitudeControlLogic(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=AttitudeControlLogic(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[PatchMisconfigurationVuln(), ControlLoopInstabilityVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Stability": "Erratic or unstable during flight",
                "Environment": "Any",
                "RemoteController": "Active",
                "CPSController": "Active",
                "Operating mode": "Any",
            },
            attack_requirements=[
                "A faulty patch applied to the attitude control logic.",
                "The vehicle performs maneuvers that rely on stable orientation control.",
                "Simulators",
                "PatchVerif codebase"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Attitude Control Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=AttitudeControlLogic(), # Add the binary abstraction here
                        modality="binary patch",
                    ),
                    required_access_level="Local or Remote",
                    configuration={"patch_type": "attitude_control"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Instability",
                    description=(
                        "The faulty patch causes the vehicle to exhibit erratic and unstable attitude control, "
                        "leading to unexpected tilting, erratic movement, or crashes."
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
                    "Instruct the vehicle to execute sharp pivoting maneuvers at varying speeds and angles.",
                    "Observe the vehicle's attitude control during standard and extreme maneuvers.",
                    "Monitor for signs of instability, such as unexpected tilting, erratic yaw, or unsteady flight paths.",
                    "Document the physical consequences, including loss of control, crashes, or potential mechanical damage.",
                    "Refine the patch for future attacks, focusing on greater disruption during more complex maneuvers."
                ]
            },
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, unstable attitude during critical maneuvers
        pass
