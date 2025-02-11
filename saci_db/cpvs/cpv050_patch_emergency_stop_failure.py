from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (EmergencyStopLogic, PWMChannel, ESC, MultiCopterMotor)

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.emergency_stop_vuln import EmergencyStopVuln
from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController

class PatchEmergencyStopFailureCPV(CPV):
    
    NAME = "The Emergency Stop Failure Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                ArduPilotController(), 
                EmergencyStopLogic(),
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=ArduPilotController(), 
            exit_component=MultiCopterMotor(),

            vulnerabilities=[EmergencyStopVuln(), PatchMisconfigurationVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Normal Operation",
                "Environment": "Open Field or Urban Area",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "A deployed faulty patch targeting emergency stop functionality.",
                "`PatchVerif` codebase",
                "Simulator"
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Emergency Stop Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=EmergencyStopLogic(), # Add the binary abstraction here
                        modality="binary patch",
                    ),
                    required_access_level="Local or Remote",
                    configuration={"patch_version": "Faulty emergency stop logic"},
                ),
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Safety Mechanism Failure",
                    description=(
                        "The faulty patch disables the emergency stop functionality, "
                        "leading to safety-critical situations where the drone fails to halt during emergencies."
                    ),
                ),
            ],

            exploit_steps = {
                "TA3 Exploit Steps": [
                    "Use optical imaging tools to catalog all components on the rover.",
                    "Identify components that contain memory that might store firmware.",
                    "Extract the firmware from the identified memory component.",
                    "Determine the firmware type and version for further analysis."
                ],
                "TA1 Exploit Steps": [
                    "Deploy the faulty patch onto the drone's flight controller via direct access or remote update mechanisms.",
                    "Revisit the ArduPilot Git commit history to identify a version containing the bug.",
                    "Modify the firmware accordingly:",
                    "    - If the current version is newer, revert the fixed patch (uncommit the fix).",
                    "    - If the current version is older, inject the buggy code snippet.",
                    "Derive the triggering condition using PatchVerif, which provides the triggering unit test input.",
                    "Report the identified triggering condition to TA3 for simulator verification."
                ],
                "TA2 Exploit Steps": [
                    "Prepare the simulator for the triggering condition reported by TA1.",
                    "Verify that the emergency stop feature has been disabled through simulator testing.",
                    "Trigger a real-world scenario requiring an emergency stop by:",
                    "    - Introducing obstacles into the drone’s flight path.",
                    "    - Simulating hardware faults or critical alerts that would normally activate the stop command.",
                    "Observe the drone's behavior and confirm that it does not respond to the emergency stop command.",
                    "Allow the drone to continue its operation unchecked, leading to potential consequences such as:",
                    "    - Collision with physical obstacles.",
                    "    - Entry into restricted or hazardous zones.",
                    "    - Loss of control resulting in a crash.",
                    "Analyze the impact of the failure and document the consequences to refine future attack strategies."
                ]
            },

            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        # TODO: Enhanced representation of the attacker's goal
        self.goal_state = []

    def in_goal_state(self, state: GlobalState) -> bool:
        # Define the logic for determining when the drone is in the attack's goal state
        return False
