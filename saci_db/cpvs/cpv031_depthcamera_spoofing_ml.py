from saci.modeling import CPV
from saci.modeling.device import ObstacleAvoidanceLogic, DepthCamera, ObjectAvoidanceDNN, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.devices.px4_quadcopter_device import PX4Controller

from saci_db.vulns.depthcamera_spoofing_vuln import DepthCameraSpoofingVuln
from saci_db.vulns.stereo_matching_vuln import StereoMatchingVuln
from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln

class MLDepthEstimationAttackCPV(CPV):
    
    NAME = "The Stereo Vision-Based Depth Camera Attack on ML-based Depth Estimation Systems"

    def __init__(self):
        super().__init__(
            required_components=[
                DepthCamera(),
                ObjectAvoidanceDNN(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(), 
            ],

            entry_component=DepthCamera(),
            exit_component=MultiCopterMotor(), 

            vulnerabilities=[DepthCameraSpoofingVuln(), DeepNeuralNetworkVuln(), StereoMatchingVuln()],

            goals=["Manipulate ML-based depth estimation to induce false obstacle perception"],

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
                "DepthEstimationModel": "DispNet, PSMNet, or AANet",
            },

            attack_requirements=[
                "Access to projectors capable of emitting adversarial light patterns",
                "Knowledge of the target's ML-based depth estimation model parameters",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Adversarial Light Pattern Injection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=DepthCamera(),
                        modality="light",
                    ),
                    required_access_level="Remote",
                    configuration={"pattern": "Adversarial light patterns"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Manipulation of Control",
                    description=(
                        "The attacker projects adversarial light patterns into the stereo camera lenses, causing the ML-based depth estimation model to produce incorrect depth maps, leading to false obstacle detection or failure to detect actual obstacles."
                    ),
                ),
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Analyze the target's ML-based depth estimation model to understand its vulnerability to specific input perturbations.",
                    "Decompile the DNN model from the CPS firmware.",
                    "Dump the source code and model weight of the DNN model",
                    "Report the DNN model and source code to TA4.",
                "TA2 Exploit Steps",
                    "Wait for the experimental setup from TA4.",
                    "Simulate the adversarial attacks in the simulator.",
                    "   - Simulate the DNN depth estimation algorithms.",
                    "   - Based on the output of TA4, simulate the visual-based attack vector.",
                "TA3 Exploit Steps",
                    "Wait for the experimental setup from TA4.",
                    "Set up projectors to emit the adversarial light patterns aimed at the stereo camera lenses.",
                    "Project the adversarial patterns during the autonomous system's operation.",
                    "The ML-based depth estimation model processes the perturbed images, resulting in incorrect depth predictions.",
                    "The obstacle avoidance system reacts based on the erroneous depth information, causing unintended or unsafe maneuvers.",
                "TA4 Exploit Steps",
                    "Wait for the dumped DNN model from TA1.",
                    "Generate adversarial light patterns tailored to exploit the model's weaknesses.",
                    "Report the adversarial pattern and experimental setups to TA2 and TA4."
            ],
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/system/files/sec22-zhou-ce.pdf",
            ],
        )
        self.goal_state = ["Obstacle avoidance system responds to manipulated depth information"]

    def in_goal_state(self, state):
        return state.get("ObstacleAvoidanceResponse") == "ActivatedDueToManipulatedDepth"