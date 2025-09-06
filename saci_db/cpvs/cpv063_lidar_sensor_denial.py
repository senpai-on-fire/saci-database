from saci.modeling import CPV
from saci.modeling.device import (
    LiDAR,
    Controller,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln


class LiDARSensorDenialCPV(CPV):
    NAME = "Low-Cost LiDAR Blinding and Jamming Attack on Sensor Input Channel"

    def __init__(self):
        super().__init__(
            required_components=[
                LiDAR(),  # This is the entry component (Required)
                # Serial(), # Removed considering that the LiDAR is inherently connected to the Controller via Serial (Not Required)
                Controller(),  # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=LiDAR(),
            exit_component=Motor(),
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
                    signal=OpticalAttackSignal(src=ExternalInput(), dst=LiDAR(), modality="light"),
                    required_access_level="Physical",
                    configuration={"mode": "Flooding", "wavelength": "Visible/IR"},
                ),
                BaseAttackVector(
                    name="Replay Attack",
                    signal=OpticalAttackSignal(src=ExternalInput(), dst=LiDAR(), modality="laser"),
                    required_access_level="Physical",
                    configuration={"mode": "Recorded pulses", "delay": "ms-scale"},
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Sensor Disruption",
                    description="Continuous light or replayed pulses prevent accurate object detection by overwhelming or confusing the LiDAR receiver.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Implement a model to simulate LiDAR sensor denial attack on the CPS dynamics.",
                "The model must include:",
                "    - LiDAR sensor characteristics.",
                "    - Light source parameters and interference patterns.",
                "    - Point cloud processing algorithms.",
                "    - Sensor fusion mechanisms.",
                "TA2 Exploit Steps",
                "Simulate the CPS dynamics under different attack scenarios",
                "Refine the attack parameters based on TA1 observations:",
                "    - Test various light source intensities and patterns.",
                "    - Analyze point cloud degradation patterns.",
                "    - Evaluate impact on object detection accuracy.",
                "TA3 Exploit Steps",
                "Execute the physical attack:",
                "    - Setup LED array or laser pointer aligned with target LiDAR.",
                "    - Configure light source parameters based on simulation results.",
                "    - Emit disruptive signals continuously or in bursts.",
                "    - Monitor LiDAR response and point cloud quality.",
            ],
            associated_files=[],
            reference_urls=[
                "https://www.blackhat.com/docs/eu-15/materials/eu-15-Petit-Self-Driving-And-Connected-Cars-Fooling-Sensors-And-Tracking-Drivers-wp1.pdf"
            ],
        )
        self.goal_state = ["ObjectDetection" == "DegradedOrJammed"]

    def in_goal_state(self, state):
        return state.get("ObjectDetection") == "DegradedOrJammed"
