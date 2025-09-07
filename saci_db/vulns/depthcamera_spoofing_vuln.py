import os.path
from clorm import Predicate
from saci.modeling.vulnerability import SpoofingVulnerability
from saci.modeling.device import Device
from saci.modeling.device.sensor.depth_camera import DepthCamera
from saci.modeling.communication import AuthenticatedCommunication, ExternalInput
from saci.modeling.attack import BaseAttackVector, OpticalAttackSignal, BaseCompEffect


# Predicate to define formal reasoning logic for depth camera spoofing attacks
class DepthCameraSpoofingPred(Predicate):
    pass


class DepthCameraSpoofingVuln(SpoofingVulnerability):
    def __init__(self):
        super().__init__(
            # The DepthCamera component is vulnerable to spoofing attacks
            component=DepthCamera(),
            # Input: Authenticated communication, potentially manipulated by an attacker
            _input=AuthenticatedCommunication(),
            # Output: Authenticated communication containing spoofed or corrupted depth data
            output=AuthenticatedCommunication(),
            # Predicate for formal reasoning about depth camera spoofing
            attack_ASP=DepthCameraSpoofingPred,
            # Logic rules for evaluating this vulnerability in formal reasoning
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "depth_camera_spoofing.lp"),
            # List of Associated CWEs:
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-925: Improper Verification of Integrity Check Value",
            ],
            attack_vectors=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Light Pattern Injection Attack",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=DepthCamera(),
                            ),
                            required_access_level="Remote",
                            configuration={"pattern": "Adversarial or Complementary light patterns"},
                        )
                    ],
                    "related_cpv": [
                        "ClassicDepthEstimationAttackCPV",
                        "MLDepthEstimationAttackCPV",
                    ],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Integrity",
                            description="Light pattern injection can cause the depth estimation algorithm to produce incorrect depth maps, leading to false obstacle detection or failure to detect actual obstacles.",
                        )
                    ],
                    "exploit_steps": [
                        "Analyze the target's depth estimation system to understand its vulnerability to specific light pattern perturbations.",
                        "Generate light patterns tailored to exploit the system's weaknesses.",
                        "Set up projectors to emit the light patterns aimed at the stereo camera lenses.",
                        "Project the patterns during the autonomous system's operation.",
                        "The depth estimation system processes the perturbed images, resulting in incorrect depth predictions.",
                        "The obstacle avoidance system reacts based on the erroneous depth information, causing unintended or unsafe maneuvers.",
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/system/files/sec22-zhou-ce.pdf",
                    ],
                }
            ],
        )

    def exists(self, device: Device) -> bool:
        # Iterate through all components of the device
        for comp in device.components:
            # Check if the component is a DepthCamera
            if isinstance(comp, DepthCamera):
                # Ensure the depth camera supports stereo vision and is enabled
                if comp.supports_stereo_vision() and comp.enabled():
                    return True  # Vulnerability exists
        return False  # No vulnerability detected if conditions are unmet
