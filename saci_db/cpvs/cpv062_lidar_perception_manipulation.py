from saci.modeling import CPV
from saci.modeling.device import LiDAR, ObjectDetector3D, PX4Controller, PWMChannel, ESC, MultiCopterMotor, Telemetry, Serial
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln
from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln

class LiDARPerceptionManipulationCPV(CPV):

    NAME = "LiDAR-Based 3D Object Injection and Removal Attack on Perception Pipeline"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),
                Serial(),
                ObjectDetector3D(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],

            entry_component=LiDAR(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[
                LiDARSpoofingVuln(),
                DeepNeuralNetworkVuln(),
            ],

            goals=[
                "Inject fake objects into 3D point cloud",
                "Remove real objects from LiDAR-based detection",
                "Manipulate obstacle perception to influence control decisions",
            ],

            initial_conditions={
                "TargetLiDAR": "First-gen or New-gen",
                "Environment": "Urban/Outdoor",
                "Lighting": "Day or Night",
                "VehicleSpeed": "Static to 60 km/h",
                "DetectorModel": "PointPillars, PV-RCNN, etc.",
            },

            attack_requirements=[
                "Spoofer capable of synchronized or high-frequency laser pulses",
                "IR tracking or photodetector (optional)",
                "Laser beam alignment and pulse tuning",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Synchronized Pattern Injection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=LiDAR(), modality="laser"
                    ),
                    required_access_level="Physical",
                    configuration={"pattern": "Car/Person", "timing": "synchronized"},
                ),
                BaseAttackVector(
                    name="Adaptive High-Frequency Removal",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=LiDAR(), modality="laser"
                    ),
                    required_access_level="Physical",
                    configuration={"mode": "A-HFR", "frequency": ">1MHz"},
                ),
                BaseAttackVector(
                    name="Relay Injection Closer Than Attacker",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=LiDAR(), modality="laser"
                    ),
                    required_access_level="Physical",
                    configuration={"mode": "Relay", "timing": "delayed"},
                ),
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Perception",
                    description="Injected or removed point clouds mislead 3D object detector, affecting obstacle awareness and trajectory planning."
                )
            ],

            exploit_steps=[
                "Deploy LiDAR spoofer near line-of-sight to target sensor.",
                "For injection: synchronize and emit crafted patterns.",
                "For removal: use high-frequency or saturating lasers.",
                "Object detector outputs incorrect detections.",
                "Control system reacts to manipulated perception.",
            ],

            associated_files=[],
            reference_urls=[
                "https://www.ndss-symposium.org/ndss-paper/lidar-spoofing-meets-the-new-gen/",
                "https://www.ndss-symposium.org/ndss-paper/on-the-realism-of-lidar-spoofing-attacks/",
                "https://eprint.iacr.org/2017/613"
            ]
        )
        self.goal_state = ["ObjectDetection" == "MisledBySpoofedPoints"]

    def in_goal_state(self, state):
        return state.get("ObjectDetection") == "MisledBySpoofedPoints"