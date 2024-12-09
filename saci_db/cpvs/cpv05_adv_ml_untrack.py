from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    ESC, DNN,
    Camera,
    MultiCopterMotor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci_db.vulns.ml_vuln import DeepNeuralNetworkVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller

class ObjectTrackCPV(CPV):
    NAME = "The Object Untracking CPV"

    def __init__(self):
        ml_vuln = DeepNeuralNetworkVuln()
        super().__init__(
            required_components=[
                Camera(),
                DNN(),
                PX4Controller(),
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=Camera(),
            exit_component=MultiCopterMotor(),
            vulnerabilities=[ml_vuln],
            goals=[],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "Any",
                "CPSController": "Any",
                "Operating mode": "Autonomous",
            },
            attack_requirements=[
                "Adversarial patches generated use adversarial machine learning",
                "Decompiled DNN model from the firmware",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Adversarial Pattern Injection",
                    signal=ImageAttackSignal(
                        src=ExternalInput(),
                        dst=DeepNeuralNetworkVuln().component,
                        modality="image",
                    ),
                    required_access_level="Remote",
                    configuration={"duration": "Transient"},
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Manipulation",
                    description=(
                        "The attacker can manipulate the autonomous CPS behavior by injecting adversarial patterns "
                    ),
                ),
            ],
            exploit_steps=[
                "Decompile the DNN model from the CPS firmware.",
                "Dump the source code and model weight of the DNN model",
                "Generate adversarial examples using adversarial machine learning-based optimization.",
                "Showcase the adversarial examples to the CPS camera for control manipulation."
            ],
            associated_files=[],
            reference_urls=[],
        )
        # TODO: Attacker's goal state represented as the distorted object bounding box
        self.goal_state_conditions = {"bounding_box": [0.0, 0.0]}

    def in_goal_state(self, state: GlobalState) -> bool:
        pass
