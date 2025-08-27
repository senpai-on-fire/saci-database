from pathlib import Path
from saci.modeling import CPV
from saci.modeling.device import SpeedControlLogic, MultiCopterMotor, PWMChannel, ESC, Motor, Serial

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.speed_control_misbehavior_vuln import SpeedControlMisbehaviorVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.device import Controller

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController


class PatchPivotTurnMalfunctionCPV(CPV):
    NAME = "The Pivot Turn Malfunction Due to Faulty Speed Control Patch"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Serial(), # This is the entry component (Required)
                Controller(), # This is the main controller where the firmware is hosted (Required)
                # SpeedControlLogic(), # Removed since it's too specific for now (Not Required) 
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[
                PatchMisconfigurationVuln(),
                SpeedControlMisbehaviorVuln(),
                ControllerIntegrityVuln(),
            ],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Constant during pivot turns",
                "Environment": "Sharp pivoting maneuver",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
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
                        dst=SpeedControlLogic(),  # Add the binary abstraction here
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
                    "Instruct the vehicle to execute sharp pivoting maneuvers at varying speeds and angles.",
                    "Observe the vehicle's behavior during these maneuvers, specifically:",
                    "    - Whether it maintains a constant, unsafe speed despite varying turning requirements.",
                    "    - Signs of instability, such as wheel lift, skidding, or wobbling.",
                    "    - Near rollovers or loss of control at sharp angles or high speeds.",
                    "Record the physical effects caused by the patch, including reduced maneuverability, instability, and safety risks.",
                    "Evaluate the long-term effects of the attack by simulating repeated pivot maneuvers to assess cumulative damage to the vehicle (e.g., mechanical strain or system degradation).",
                    "Document the results of the exploit, including observations, key metrics (e.g., speed consistency during maneuvers), and outcomes (e.g., rollovers or crashes).",
                    "Analyze the impact of the failure and document the consequences to refine future attack strategies.",
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
        # For example, if the vehicle is unstable during sharp pivot turns
        pass
