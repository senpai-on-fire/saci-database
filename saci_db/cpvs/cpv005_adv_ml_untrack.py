from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (
    ESC,
    Telemetry,
    DNNTracking,
    Camera,
    PWMChannel,
    MultiCopterMotor,
    Serial,
    Motor,
)

from saci.modeling.communication import ExternalInput
from saci.modeling.state import GlobalState

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import Controller

from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller


class ObjectTrackCPV(CPV):
    NAME = "The Object Untracking Attack on AI models"

    def __init__(self):
        super().__init__(
            required_components=[
                Camera(), # This is the entry component (Required)
                # Serial(), # Removed considering that the camera is inherently connected to the Controller via Serial (Not Required)
                # DNNTracking(), # Removed, assuming the DNNTracking model is part of the control system (Not Required)
                Controller(), # Changed from PX4Controller() to Controller() for generalization (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Camera(),
            exit_component=Motor(),
            
            vulnerabilities=[DeepNeuralNetworkVuln(), ControllerIntegrityVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "Any",
                "CPSController": "Any",
                "Operating mode": "Mission",
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
                "TA1 Exploit Steps",
                "Decompile the DNN model from the CPS firmware.",
                "Dump the source code and model weight of the DNN model",
                "TA2 Exploit Steps",
                "Simulate the adversarial attacks in the simulator.",
                "   - Simulate the DNN tracking algorithms.",
                "   - Based on the output of TA4, simulate the visual-based attack vector.",
                "TA3 Exploit Steps",
                "Showcase the adversarial examples to the CPS camera for control manipulation."
                "TA4 Exploit Steps",
                "Wait for the dumped DNN model from TA1.",
                "Generate adversarial examples using adversarial machine learning-based optimization.",
            ],
            
            associated_files=[],
            reference_urls=[],
        )
        # TODO: Attacker's goal state represented as the distorted object bounding box
        self.goal_state_conditions = {"bounding_box": [0.0, 0.0]}

    def in_goal_state(self, state: GlobalState) -> bool:
        pass
