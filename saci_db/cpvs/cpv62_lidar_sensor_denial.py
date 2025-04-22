from saci.modeling import CPV
from saci.modeling.device import LiDAR, ObjectDetector3D, PX4Controller, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln

class LiDARSensorDenialCPV(CPV):

    NAME = "Low-Cost LiDAR Blinding and Jamming Attack on Sensor Input Channel"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),
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
            ],

            goals=[
                "Blind or jam LiDAR to reduce point cloud reliability",
                "Prevent accurate 3D reconstruction by the vehicle",
            ],

            initial_conditions={
                "TargetLiDAR": "Ibeo Lux 3 or similar",
                "Environment": "Controlled/Lab",
                "Lighting": "Low light preferred",
                "AttackerResources": "Laser pointer, LED array (<$60)",
            },

            attack_requirements=[
                "Commodity light source with sufficient intensity",
                "Line-of-sight to LiDAR",
                "No need for synchronization or tracking",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="LED Blinding",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=LiDAR(), modality="light"
                    ),
                    required_access_level="Physical",
                    configuration={"mode": "Flooding", "wavelength": "Visible/IR"},
                ),
                BaseAttackVector(
                    name="Replay Attack",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=LiDAR(), modality="laser"
                    ),
                    required_access_level="Physical",
                    configuration={"mode": "Recorded pulses", "delay": "ms-scale"},
                ),
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Sensor Disruption",
                    description="Continuous light or replayed pulses prevent accurate object detection by overwhelming or confusing the LiDAR receiver."
                )
            ],

            exploit_steps=[
                "Setup LED array or laser pointer aligned with target LiDAR.",
                "Emit disruptive signals continuously or in bursts.",
                "LiDAR experiences degraded sensing or returns invalid point clouds.",
                "Sensor fusion fails or outputs incorrect map of environment.",
            ],

            associated_files=[],
            reference_urls=[
                "https://www.blackhat.com/docs/eu-15/materials/eu-15-Petit-Self-Driving-And-Connected-Cars-Fooling-Sensors-And-Tracking-Drivers-wp1.pdf"
            ]
        )
        self.goal_state = ["ObjectDetection" == "DegradedOrJammed"]

    def in_goal_state(self, state):
        return state.get("ObjectDetection") == "DegradedOrJammed"