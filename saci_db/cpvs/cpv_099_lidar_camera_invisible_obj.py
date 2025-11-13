from saci.modeling import CPV
from saci.modeling.device import Camera, Controller, Lidar, Motor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln


class LiDARCameraInvisibleObjectCPV(CPV):
    NAME = "Adversarial 3D Object LiDAR/Camera Fusion Perception"

    def __init__(self):
        super().__init__(
            required_components=[
                Lidar(),
                Camera(),
                Controller(),
                Motor(),
            ],
            entry_component=Lidar(),
            exit_component=Motor(),
            vulnerabilities=[DeepNeuralNetworkVuln()],
            initial_conditions={
                "Position": "CPS rover approaches a tracked obstacle within perception range on the mission lane",
                "Heading": "Aligned with the mission lane and unobstructed line-of-sight",
                "Speed": "Any (>0)",
                "Environment": "Indoor or controlled outdoor",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Physical access within perception range to place the adversarial object"
                "3D-print stealth-constrained mesh"
                "Clear line-of-signt to LiDAR and camera sensors"
                "Understanding of LiDAR and camera detection thresholds"
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Adversarial 3D Mesh LiDAR Detection Bypass",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=Lidar(),
                    ),
                    required_access_level="Physical",
                    configuration={
                        "object": "3D-printed adversarial object with stealth-constrained vertices",
                        "placement": "Centered in the CPS lane at braking distance to corrupt LiDAR voxels",
                        "goal": "Fail to detect the object",
                        "effect": "Prevents the CPS from braking",
                    },
                ),
                BaseAttackVector(
                    name="Adversarial 3D Mesh MSF Detection Bypass",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=Camera(),
                    ),
                    required_access_level="Physical",
                    configuration={
                        "object": "Same 3D-printed adversarial object with stealth-constrained vertices",
                        "placement": "Center of the CPS lane and 7 m ahead so camera and LiDAR view the object simultaneously",
                        "goal": "Fail to detect the object",
                        "effect": "Prevents the CPS from braking",
                    },
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="3D printed adversarial objects simultaneously evade LiDAR and camera detections, potentially leading to collisions.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Collect synchronized LiDAR/camera logs with calibration matrices for the CPS mission lane",
                "Port the victim's MSF perception stack (camera + LiDAR fusion) for loss and confidence queries",
                "Extract a benign mesh (traffic cone, cube, bench) and enforce stealth constraints",
                "Implement the MSF-ADV differentiable rendering pipeline to synthesize LiDAR voxels and camera pixels",
                "Run loss optimization to minimize detection confidence"
                "Report the adversarial mesh and experimental setups to TA2"
                "TA2 Exploit Steps",
                "Simulate the adversarial attacks in the simulator",
                "Validate the adversarial mesh on in simulation",
                "Report the findings to TA3",
                "TA3 Exploit Steps",
                "Execute the physical attack in real environment",
                "Deploy the object mid-lane and align it with both LiDAR and camera fields-of-view",
                "Monitor real sensor feeds to verify detection confidence while the rover keeps its commanded speed into the obstacle",
                "Vertify the attack is successful"
            ],
            associated_files=[],
            reference_urls=[
                "https://arxiv.org/abs/2106.09249",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("MSFObstacleHidden", True)
