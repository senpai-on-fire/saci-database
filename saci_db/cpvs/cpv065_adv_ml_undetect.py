from saci.modeling import CPV
from saci.modeling.device import Camera, PX4Controller, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.adv_ml_undetect_patch_vuln import AdvMLUndetectPatchVuln

class AdvMLUndetectCPV(CPV):

    NAME = "Physical Patch Attack to Evade Aerial Object Detection"

    def __init__(self):
        super().__init__(
            required_components=[
                Camera(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],

            entry_component=Camera(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[
                AdvMLUndetectPatchVuln(),
            ],

            goals=[
                "Prevent aerial object detector from recognizing target vehicles",
            ],

            initial_conditions={
                "TargetDetector": "YOLOv3 trained on COWC-M dataset",
                "CameraPlatform": "Drone at 40/60m altitude",
                "Environment": "Side Street / Car Park",
                "AttackerKnowledge": "White-box",
            },

            attack_requirements=[
                "Ability to place printed patches physically on or around vehicle",
                "Access to model architecture and weights",
                "No modification to model software or hardware",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Adversarial Patch",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=Camera(), modality="visual-pattern"
                    ),
                    required_access_level="Physical",
                    configuration={
                        "patch_shape": "Rectangular or U-shape",
                        "augmentation": "Geometric + Color-space",
                        "placement": "Roof / Ground around vehicle",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="ML-Based Object Detection Evasion",
                    description="Physical patches significantly reduce detection scores, preventing car recognition from aerial images."
                )
            ],

            exploit_steps=[
                "Optimize adversarial patch using objectness loss + NPS + TV losses",
                "Print patch and place it physically in the target scene",
                "Capture aerial images using drone or balcony-mounted camera",
                "Run detector on patched scene and observe reduced objectness score",
                "Target vehicles are no longer detected or assigned low scores",
            ],

            associated_files=[],
            reference_urls=[
                'https://openaccess.thecvf.com/content/WACV2022/papers/Du_Physical_Adversarial_Attacks_on_an_Aerial_Imagery_Object_Detector_WACV_2022_paper.pdf',
            ]
        )

        self.goal_state = [{"CarDetection": "Suppressed"}]

    def in_goal_state(self, state):
        return state.get("CarDetection") == "Suppressed"
