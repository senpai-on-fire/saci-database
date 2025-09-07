from saci.modeling import CPV
from saci.modeling.device import (
    Camera,
    Controller,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln


class AdvMLUndetectCPV(CPV):
    NAME = "Physical Patch Attack to Evade Aerial Object Detection"

    def __init__(self):
        super().__init__(
            required_components=[
                Camera(),  # This is the entry component (Required)
                # Serial(), # Removed considering that the Camera is inherently connected to the Controller via Serial (Not Required)
                Controller(),  # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Camera(),
            exit_component=Motor(),
            vulnerabilities=[
                DeepNeuralNetworkVuln(),
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
                    signal=OpticalAttackSignal(src=ExternalInput(), dst=Camera(), modality="visual-pattern"),
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
                    description="Physical patches significantly reduce detection scores, preventing car recognition from aerial images.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Implement a Model to simulate the adversarial patch attack on object detection",
                "The model must include:",
                "    - Objectness loss optimization algorithm",
                "    - NPS (Non-Printability Score) calculation",
                "    - TV (Total Variation) loss computation",
                "    - YOLOv3 detector simulation with COWC-M dataset",
                "TA2 Exploit Steps",
                "Simulate the physical patch attack and its effects",
                "The simulation must include:",
                "    - Patch optimization for different vehicle types",
                "    - Geometric and color-space augmentation effects",
                "    - Impact analysis on detection scores",
                "    - Verification of attack effectiveness in different environments",
                "TA3 Exploit Steps",
                "Execute the physical attack in real environment",
                "Print optimized adversarial patches",
                "Place patches on vehicle roof or ground around target",
                "Deploy drone or balcony-mounted camera at 40/60m altitude",
                "Capture aerial images of patched scene",
                "Run YOLOv3 detector on captured images",
                "Verify successful suppression of car detection",
            ],
            associated_files=[],
            reference_urls=[
                "https://openaccess.thecvf.com/content/WACV2022/papers/Du_Physical_Adversarial_Attacks_on_an_Aerial_Imagery_Object_Detector_WACV_2022_paper.pdf",
            ],
        )

        self.goal_state = [{"CarDetection": "Suppressed"}]

    def in_goal_state(self, state):
        return state.get("CarDetection") == "Suppressed"
