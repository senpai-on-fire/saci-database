from saci.modeling import CPV
from saci.modeling.device import AttitudeControlLogic, Motor, Serial

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.binary_patching_attack import BinaryPatchingAttack

from saci_db.vulns.patch_misconfiguration_vuln import PatchMisconfigurationVuln
from saci_db.vulns.control_loop_instability_vuln import ControlLoopInstabilityVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln


from saci.modeling.device import Controller


class PatchUnstableAttitudeControlCPV(CPV):
    NAME = "The Unstable Attitude Control Due to Faulty Patch"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),  # This is the entry component (Required)
                Controller(),  # This is the main controller where the firmware is hosted (Required)
                # AttitudeControlLogic(), # Removed since it's too specific for now (Not Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Serial(),
            exit_component=Motor(),
            vulnerabilities=[
                PatchMisconfigurationVuln(),
                ControlLoopInstabilityVuln(),
                ControllerIntegrityVuln(),
            ],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Stability": "Erratic or unstable during flight",
                "Environment": "Any",
                "RemoteController": "Active",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "A faulty patch applied to the attitude control logic.",
                "The vehicle performs maneuvers that rely on stable orientation control.",
                "Simulators",
                "PatchVerif codebase",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Faulty Attitude Control Patch",
                    signal=BinaryPatchingAttack(
                        src=ExternalInput(),
                        dst=AttitudeControlLogic(),  # Add the binary abstraction here
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
                "Observe the vehicle’s attitude control during both standard and extreme maneuvers.",
                "Monitor for signs of instability, such as:",
                "    - Unexpected tilting.",
                "    - Erratic yaw movements.",
                "    - Unsteady flight paths.",
                "Document the physical consequences, including:",
                "    - Loss of control.",
                "    - Crashes.",
                "    - Potential mechanical damage.",
                "Refine the patch for future attacks, focusing on increasing disruption during complex maneuvers.",
                "TA3 Exploit Steps",
                "Use optical imaging tools to catalog all components on the CPS.",
                "Identify components that contain memory that might store firmware.",
                "Extract the firmware from the memory component.",
                "Identify the firmware type and version.",
            ],
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/usenixsecurity23-kim-hyungsub.pdf"],
        )
        self.goal_state = []

    def in_goal_state(self, state):
        # Define conditions when the vehicle is in the attack's goal state
        # For example, unstable attitude during critical maneuvers
        pass
