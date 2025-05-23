from saci.modeling import CPV
from saci.modeling.device import (
    ObstacleAvoidanceLogic,
    Telemetry,
    DepthCamera,
    PWMChannel,
    ESC,
    MultiCopterMotor,
    Serial,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller

from saci_db.vulns.depthcamera_spoofing_vuln import DepthCameraSpoofingVuln
from saci_db.vulns.stereo_matching_vuln import StereoMatchingVuln


class ClassicDepthEstimationAttackCPV(CPV):
    NAME = "The Stereo Vision-Based Depth Camera Attack on Classic Depth Estimation Systems"

    def __init__(self):
        super().__init__(
            required_components=[
                DepthCamera(),
                Serial(),
                ObstacleAvoidanceLogic(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=DepthCamera(),
            exit_component=ObstacleAvoidanceLogic(),
            vulnerabilities=[DepthCameraSpoofingVuln(), StereoMatchingVuln()],
            goals=["Induce false depth perception to mislead obstacle avoidance"],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "None",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "None",
                "Operating mode": "Mission",
                "LightingConditions": "Controlled",
                "DistanceToTarget": "Within effective range",
                "StereoAlgorithm": "BM or SGBM",
            },
            attack_requirements=[
                "Access to projectors capable of emitting controlled light patterns",
                "Knowledge of the target's stereo vision system parameters",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Projected Light Pattern Injection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=DepthCamera(),
                        modality="light",
                    ),
                    required_access_level="Remote",
                    configuration={"pattern": "Complementary light sources"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description=(
                        "The attacker projects specific light patterns into the stereo camera lenses, causing the depth estimation algorithm to perceive non-existent obstacles or misjudge actual obstacles' distances."
                    ),
                ),
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Analyze the target's stereo vision system to determine the stereo matching algorithm in use.",
                "Report the stereo camera setups to TA2 and TA4.",
                "TA2 Exploit Steps",
                "Simulate the stereo vision system in simulator for collision avoidance based on TA4.",
                "Simulate the light projecting to the stereo camera following the setups indentified by TA4.",
                "TA3 Exploit Steps",
                "Set up two projectors to emit complementary light patterns aimed at each lens of the stereo camera based on TA4.",
                "Project the light patterns simultaneously, ensuring one pattern is more prominent in one lens than the other.",
                "The disparity in light intensity between the two images leads to incorrect stereo matching, resulting in false depth perception.",
                "The obstacle avoidance system reacts to the perceived obstacles, causing unintended maneuvers.",
                "TA4 Exploit Steps",
                "Identify the projector setups based on the stereo vision system's characteristics.",
                "Report to the projector setups to TA2 and TA3 for CPV verification in the simulator and physical environment.",
            ],
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/system/files/sec22-zhou-ce.pdf",
            ],
        )
        self.goal_state = [
            "Obstacle avoidance system responds to false depth information"
        ]

    def in_goal_state(self, state):
        return state.get("ObstacleAvoidanceResponse") == "ActivatedDueToFalseObstacle"
