"""
Modeling the adversarial examples attack
The modeled impact is: attackers can control the output of DNN models by exploiting known model parameters.
"""

import os.path

from clorm import Predicate

from saci.modeling import BaseVulnerability
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.image_attack_signal import ImageAttackSignal
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack import BaseCompEffect

from saci.modeling.device import Device, DNNTracking, DepthCamera
from saci.modeling.communication import (
    AuthenticatedCommunication,
    ExternalInput,
)


# Predicate to define formal reasoning logic for vulnerabilities in deep neural networks (DNNs)
class DeepNeuralNetworkPred(Predicate):
    pass


class DeepNeuralNetworkVuln(BaseVulnerability):
    def __init__(self):
        dest_component = DNNTracking()
        super().__init__(
            # The DNN component, vulnerable to adversarial example attacks
            component=dest_component,
            # Input: Authenticated communication representing crafted adversarial inputs
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication leading to attacker-controlled or misclassified outputs
            output=AuthenticatedCommunication(),
            # Predicate for reasoning about adversarial vulnerabilities in DNNs
            attack_ASP=DeepNeuralNetworkPred,
            # Logic rules for evaluating adversarial attacks in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "adversarial_ml.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-20: Improper Input Validation",
                "CWE-285: Improper Authorization",
                "CWE-347: Improper Verification of Cryptographic Signature",
                "CWE-125: Out-of-Bounds Read",
                "CWE-326: Inadequate Encryption Strength",
                "CWE-400: Uncontrolled Resource Consumption",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1188: Insecure Default Initialization of Resource",
                "CWE-489: Active Debug Code",
            ],
            attack_vectors=[
                {
                    # List of related attack vectors and their exploitation information
                    "attack_vector": [
                        BaseAttackVector(
                            name="Adversarial Pattern Injection",
                            signal=ImageAttackSignal(
                                src=ExternalInput(),
                                dst=dest_component,
                                modality="image",
                            ),
                            required_access_level="Remote",
                            configuration={"duration": "Transient"},
                        )
                    ],
                    # List of associated CPVs
                    "related_cpv": ["ObjectTrackCPV"],
                    # List of associated component-level attack effects
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="Injection of adversarial patterns corrupts sensor inputs, undermining the integrity of the DNN's decisions.",
                    ),
                    # Steps of exploiting this attack vector
                    "exploit_steps": [
                        "Decompile the DNN model from the CPS firmware.",
                        "Dump the source code and model weight of the DNN model",
                        "Generate adversarial examples using adversarial machine learning-based optimization.",
                        "Showcase the adversarial examples to the CPS camera for control manipulation.",
                    ],
                    # List of related references
                    "reference_urls": [],
                },
                {
                    "attack_vector": [
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
                    "related_cpv": ["MLDepthEstimationAttackCPV"],
                    "comp_attack_effect": BaseCompEffect(
                        category="Integrity",
                        description="Projection of adversarial light patterns distorts the depth camera input, compromising the integrity of sensor data and leading to incorrect obstacle detection.",
                    ),
                    "exploit_steps": [
                        "Analyze the target's ML-based depth estimation model to understand its vulnerability to specific input perturbations.",
                        "Generate adversarial light patterns tailored to exploit the model's weaknesses.",
                        "Set up projectors to emit the adversarial light patterns aimed at the stereo camera lenses.",
                        "Project the adversarial patterns during the autonomous system's operation.",
                        "The ML-based depth estimation model processes the perturbed images, resulting in incorrect depth predictions.",
                        "The obstacle avoidance system reacts based on the erroneous depth information, causing unintended or unsafe maneuvers.",
                    ],
                    "reference_urls": ["https://www.usenix.org/system/files/sec22-zhou-ce.pdf"],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a DNN model
            if isinstance(comp, DNNTracking):
                # Verify if the DNN model's source code and weights are known
                if comp.known_source and comp.known_weight:
                    # If both the source and weights are accessible, the model is vulnerable
                    # An attacker can craft adversarial examples to control the model's output
                    return True
        return False  # No vulnerability detected if conditions are not met
