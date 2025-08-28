import os
from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, LiDAR
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack import (
    BaseAttackVector,
    BaseCompEffect,
    EnvironmentalInterference,
    OpticalAttackSignal,
)


class LiDARSpoofingPred(Predicate):
    pass


class LiDARSpoofingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            component=LiDAR(),
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            output=UnauthenticatedCommunication(),
            attack_ASP=LiDARSpoofingPred,
            rulefile=os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "lidar_spoofing.lp"
            ),
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1254: Improper Handling of Transparent or Translucent Inputs",
            ],
            attack_vectors=[
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Direct LiDAR Laser Injection",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=LiDAR(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": [
                                    "IR laser injection",
                                    "Pulse timing manipulation",
                                ],
                                "modality": "850nm IR laser",
                                "precision": "Line-of-sight to receiver",
                                "target_effect": "False obstacle detection",
                                "detection_range": "Within 27 inches",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARSpoofingStopCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                            description="Direct laser injection causes LiDAR to detect false obstacles, triggering emergency stop behavior.",
                        )
                    ],
                    "exploit_steps": [
                        "Power on system and verify normal operation",
                        "Aim IR laser at LiDAR receiver (left side)",
                        "Use non-IR blocking camera for alignment",
                        "Trigger false obstacle detection",
                        "Observe emergency stop behavior",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV005/HII-NGP1AROV2ARR05-CPV005-20250425.docx"
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Mirror-Based LiDAR Signal Redirection",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=LiDAR(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": [
                                    "Signal redirection",
                                    "Distance manipulation",
                                ],
                                "material": "Reflective mirror (4x4 inches min)",
                                "angle": "45° relative to sensor plane",
                                "placement": "Within 27 inches of sensor",
                                "target_effect": "Obstacle detection bypass",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARBYPASSMirrorCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                            description="Mirror-based signal redirection prevents obstacle detection, allowing potential collisions.",
                        )
                    ],
                    "exploit_steps": [
                        "Verify baseline obstacle detection",
                        "Position mirror at 45° angle",
                        "Ensure proper surface alignment",
                        "Place real obstacle behind mirror",
                        "Confirm detection bypass",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV003/HII-NGP1AROV2ARR05-CPV003-20250419.docx"
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="LiDAR Sensor Denial Attack",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=LiDAR(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": ["LED flooding", "Pulse replay"],
                                "modality": ["Visible/IR light", "Recorded pulses"],
                                "hardware": "Laser pointer or LED array (<$60)",
                                "environment": "Low light preferred",
                                "target_effect": "Sensor blinding/jamming",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARSensorDenialCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Sensor Disruption",
                            description="Continuous light or replayed pulses prevent accurate object detection by overwhelming or confusing the LiDAR receiver.",
                        )
                    ],
                    "exploit_steps": [
                        "Setup LED array or laser pointer aligned with target LiDAR",
                        "Emit disruptive signals continuously or in bursts",
                        "Verify degraded sensing or invalid point clouds",
                        "Confirm sensor fusion failure or incorrect mapping",
                        "Document attack effectiveness and recovery behavior",
                    ],
                    "reference_urls": [
                        "https://www.blackhat.com/docs/eu-15/materials/eu-15-Petit-Self-Driving-And-Connected-Cars-Fooling-Sensors-And-Tracking-Drivers-wp1.pdf"
                    ],
                },
                {
                    "attack_vector": [
                        EnvironmentalInterference(
                            dst=LiDAR(), modality="non-reflective material"
                        )
                    ],
                    "related_cpv": ["LiDARLightAbsorbCPV"],
                    "com_attack_effect": [
                        BaseCompEffect(
                            category="Manipulation of Perception",
                            description="When the LiDAR sensor emits towards the absorbant non-reflective material, it will not perceive the obstacle in that direction and assume it is a safe path to traverse.",
                        )
                    ],
                    "exploit_steps": [
                        "Set up an environment with the obstacle covered in the non-reflective material.",
                        "Deploy the system in the environment and verify the incorrect point cloud.",
                        "Confirm if incorrect point cloud has affected the CPS movement logic.",
                        "Document attack effectiveness and recovery behavior.",
                    ],
                    "reference_urls": [
                        "https://github.com/senpai-on-fire/ngc2_taskboard/tree/main/CPVs/HII-NGP1AROV2ARR05-CPV020"
                    ],
                },
            ],
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, LiDAR):
                if not comp.has_signal_validation():
                    return True
        return False
