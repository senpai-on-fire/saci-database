from saci.modeling import CPV
from saci.modeling.device import Camera, DeepLearningModel, PX4Controller, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.ml_misnavigation_patch_vuln import MLMisnavigationPatchVuln

class MLMisnavigationCPV(CPV):

    NAME = "RPAU: Robust Physical Patch Attack Causing Drone Misnavigation"

    def __init__(self):
        super().__init__(
            required_components=[
                Camera(),
                DeepLearningModel(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],

            entry_component=Camera(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[
                MLMisnavigationPatchVuln(),
            ],

            goals=[
                "Mislead the UAV to crash into an obstacle, to change direction, or to stop moving",
            ],

            initial_conditions={
                "TargetModel": "Navigation-Avoidance CNN",
                "Camera": "Monocular, 30Hz, RGB",
                "FlightEnvironment": "Outdoor / Indoor Corridor",
                "AttackerKnowledge": "White-box model access",
                "PatchSize": "50cm x 50cm",
            },

            attack_requirements=[
                "White-box access to victim model",
                "Ability to place physical patch in UAV field-of-view",
                "No interference with UAV hardware/software directly",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Physical Adversarial Patch",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=Camera(), modality="visual-pattern"
                    ),
                    required_access_level="Physical",
                    configuration={
                        "mode": "PatchPlacement",
                        "target_effect": "crash into an obstacle/ change direction/ stop moving",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Navigation Misbehavior",
                    description="UAV crashes into obstacles, deflects from path, or halts unnecessarily"
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Implement a Model to simulate the adversarial patch attack",
                    "The model must include:",
                        "    - FASC+T joint optimization algorithm for patch generation",
                        "    - Navigation model simulation and behavior prediction",
                        "    - Camera sensor simulation for patch capture",
                        "    - UAV control system response simulation",

                "TA2 Exploit Steps",
                    "Simulate the physical patch attack and its effects",
                    "The simulation must include:",
                        "    - Patch placement optimization in different environments",
                        "    - Impact analysis on navigation decisions",
                        "    - Verification of attack effectiveness",

                "TA3 Exploit Steps",
                    "Execute the physical attack in real environment",
                    "Print the adversarial patch using the optimized design",
                    "Place the patch on obstacle, floor, or wall in UAV's path",
                    "Monitor UAV behavior for successful attack execution",
                    "Verify attack impact"
            ],

            associated_files=[],
            reference_urls=[
            'https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=10265297'
            ]
        )

        self.goal_state = [{"NavigationStatus": "Crashed"}, {"NavigationStatus": "Halted"}, {"NavigationStatus": "YawDeviation"}]

    def in_goal_state(self, state):
        return state.get("NavigationStatus") in ["Crashed", "Halted", "YawDeviation"]
