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

from saci_db.devices.px4_quadcopter_device import PX4Controller

class PatchEmergencyStopFailureCPV(CPV):
    
    NAME = "The Emergency Stop Failure Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                EmergencyStopLogic(),
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=EmergencyStopLogic(),
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
                "Operating mode": "Any",
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
                    "Use Optical imaging tools to catalog all of the components on the rover.",
                    "Identify which components contained memory that might contain firmware."
                ],
                "TA2 Exploit Steps": [
                    "Extract the firmware from the memory component.",
                    "Identify the firmware type and version.",
                    "Deploy the faulty patch onto the drone's flight controller, either through direct access or remote update mechanisms.",
                    "This steps can be done by revisit the ArduPilot git commit history.",
                    "Find the version which has this bugs and inject the code snippet.",
                    "If the current version is newer, uncommit the fixed patch.",
                    "If the current version is older, add the code snippet.",
                    "Derive the triggering condition by running PatchVerif, which gives the triggering unit test input.",
                    "Report the triggering condition to TA3 for simulator verification."
                ],
                "TA1 Exploit Steps": [
                    "Prepare the simulator for the triggering condition reported by TA2.",
                    "Confirm that the emergency stop feature has been disabled by testing in a simulator.",
                    "Trigger a real-world scenario requiring the emergency stop, such as:",
                    "    - Introducing obstacles into the drone's flight path.",
                    "    - Simulating hardware faults or critical alerts to activate the emergency stop command.",
                    "Observe the drone's behavior and confirm that it does not respond to the emergency stop command.",
                    "Allow the drone to continue its operation unchecked, causing one or more of the following outcomes:",
                    "    - Collision with physical obstacles.",
                    "    - Entry into restricted or hazardous zones.",
                    "    - Loss of control leading to crashes.",
                    "Analyze the impact of the failure and document the consequences to refine future attacks."
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
