from saci.modeling import CPV
from saci.modeling.device import CyberComponentBase, ESC, DepthCamera, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci_db.vulns.depth_camera_vuln import DepthCameraSpoofingVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class DepthCameraDoSCPV(CPV):
    NAME = "The Depth Camera Laser DoS CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                DepthCamera(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=DepthCamera(),
            exit_component=MultiCopterMotor(),
            vulnerabilities=[DepthCameraSpoofingVuln()],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "Any",
                "CPSController": "Any",
                "Operating mode": "Any",
            },
            attack_requirements=["Laser projector or high-lumen flashlight"],
            attack_vectors=[
                BaseAttackVector(
                    name="Laser Projection Interference",
                    signal=ImageAttackSignal(
                        src=ExternalInput(),
                        dst=DepthCameraSpoofingVuln().component,
                        modality="laser light",
                    ),
                    required_access_level="Physical",
                    configuration={"pattern": "beam", "duration": "permanent"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description="The attacker can take control of the drone by making the drone believe there is obstacle ahead."
                )
            ],
            exploit_steps=[
                "Aim two laser projector at the depth camera lens.",
                "Project high-intensity light beams in a defined pattern to interfere with depth estimation.",
                "Monitor and adjust the pattern to maintain a continuous disruption."
                "Observe the false collision avoidance of the autonomous drone."
            ],
            associated_files=[],
            reference_urls=["https://www.usenix.org/system/files/sec22-zhou-ce.pdf"],
        )

    def in_goal_state(self, state):
        pass