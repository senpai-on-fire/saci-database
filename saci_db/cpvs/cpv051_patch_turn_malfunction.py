from pathlib import Path
from saci.modeling import CPV
from saci.modeling.device import SpeedControlLogic, MultiCopterMotor, PWMChannel, ESC

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.speed_control_misbehavior_vuln import SpeedControlMisbehaviorVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class PatchPivotTurnMalfunctionCPV(CPV):
    
    NAME = "The Pivot Turn Malfunction Due to Faulty Speed Control Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                SpeedControlLogic(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=SpeedControlLogic(),
            exit_component=MultiCopterMotor(),
            
            vulnerabilities=[PatchMisconfigurationVuln(), SpeedControlMisbehaviorVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Constant during pivot turns",
                "Environment": "Sharp pivoting maneuver",
                "RemoteController": "Active",
                "CPSController": "Active",
                "Operating mode": "Any",
            },
            attack_requirements=[
                "A faulty patch applied to the speed control logic.",
                "The vehicle performs a sharp pivoting maneuver.",
                "PatchVerif codebase",
                "Simulators",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Speed Control Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=SpeedControlLogic(), # Add the binary abstraction here
                        modality="binary patch",
                    ),
                    required_access_level="Local or Remote",
                    configuration={"patch_type": "pivot_turn_speed_control"},
                ),
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Control Malfunction",
                    description=(
                        "The faulty patch causes the vehicle to maintain an unsafe constant speed during pivot turns, "
                        "resulting in increased likelihood of rollovers or loss of stability."
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
                    "Observe the vehicle's behavior during the maneuvers, specifically:",
                    "   - Whether it maintains a constant, unsafe speed despite varying turning requirements.",
                    "   - Signs of instability, such as wheel lift, skid, or wobble.",
                    "   - Near rollover or loss of control at sharp angles or high speeds.",
                    "Record the physical effects caused by the patch, including reduced maneuverability, instability, and safety risks.",
                    "Evaluate the long-term effects of the attack by simulating repeated pivot maneuvers to assess cumulative damage to the vehicle (e.g., mechanical strain or system degradation).",
                    "Document the results of the exploit, including observations, metrics (e.g., speed consistency during maneuvers), and outcomes (e.g., rollovers or crashes).",
                    "Analyze the impact of the failure and document the consequences to refine future attacks."
                ]
            },

            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, if the vehicle is unstable during sharp pivot turns
        pass
