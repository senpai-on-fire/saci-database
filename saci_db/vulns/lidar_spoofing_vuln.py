import os
from clorm import Predicate

from saci.modeling import PublicSecretVulnerability
from saci.modeling.device import Device, LiDAR
from saci.modeling.communication import UnauthenticatedCommunication, ExternalInput
from saci.modeling.attack_vector import BaseAttackVector, OpticalAttackSignal, BaseCompEffect

class LiDARSpoofingPred(Predicate):
    pass

class LiDARSpoofingVuln(PublicSecretVulnerability):
    def __init__(self):
        super().__init__(
            component=LiDAR(),
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            output=UnauthenticatedCommunication(),
            attack_ASP=LiDARSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lidar_spoofing.lp'),
            associated_cwe=[
                "CWE-346: Origin Validation Error",
                "CWE-290: Authentication Bypass by Capture-replay",
                "CWE-20: Improper Input Validation",
                "CWE-693: Protection Mechanism Failure",
                "CWE-1254: Improper Handling of Transparent or Translucent Inputs"
            ],
            attack_vectors_exploits = [
                {
                    "attack_vector": [BaseAttackVector(
                        name="LiDAR Perception Injection Attack",
                        signal=OpticalAttackSignal(
                            src=ExternalInput(),
                            dst=LiDAR(),
                        ),
                        required_access_level="Physical",
                        configuration={
                            "methods": ["Pattern injection", "Pulse relay spoofing"],
                            "modality": "Laser pulses",
                            "precision": "Synchronized or delayed",
                            "target_effect": "3D point cloud injection"
                        },
                    )],
                    "related_cpv": ["LiDARPerceptionManipulation"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Manipulation of Perception',
                            description='Spoofed or injected laser pulses cause LiDAR to produce false 3D points, resulting in perception of fake or altered objects.'
                        )
                    ],
                    "exploit_steps": [
                        "Deploy LiDAR spoofer near line-of-sight to target sensor.",
                        "For injection: synchronize and emit crafted patterns.",
                        "For removal: use high-frequency or saturating lasers.",
                        "Object detector outputs incorrect detections.",
                        "Control system reacts to manipulated perception.",
                    ],
                    "reference_urls": [
                        "https://www.ndss-symposium.org/ndss-paper/lidar-spoofing-meets-the-new-gen/",
                        "https://www.ndss-symposium.org/ndss-paper/on-the-realism-of-lidar-spoofing-attacks/",
                        "https://eprint.iacr.org/2017/613"
                    ]
                },
                {
                    "attack_vector": [BaseAttackVector(
                        name="LiDAR Sensor Denial Attack",
                        signal=OpticalAttackSignal(
                            src=ExternalInput(),
                            dst=LiDAR(),
                        ),
                        required_access_level="Physical",
                        configuration={
                            "methods": ["LED flooding", "Laser saturation"],
                            "modality": "Continuous light",
                            "range": "< 5 meters",
                            "effect": "Sensor overload or blinding"
                        },
                    )],
                    "related_cpv": ["LiDARSensorDenial"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category='Sensor Disruption',
                            description='Saturation of the LiDAR receiver using high-intensity light sources leads to invalid, missing, or corrupted sensor data.'
                        )
                    ],
                    "exploit_steps": [
                        "Setup LED array or laser pointer aligned with target LiDAR.",
                        "Emit disruptive signals continuously or in bursts.",
                        "LiDAR experiences degraded sensing or returns invalid point clouds.",
                        "Sensor fusion fails or outputs incorrect map of environment.",
                    ],
                    "reference_urls": [
                        "https://www.blackhat.com/docs/eu-15/materials/eu-15-Petit-Self-Driving-And-Connected-Cars-Fooling-Sensors-And-Tracking-Drivers-wp1.pdf"
                    ]
                }
            ]
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, LiDAR):
                if not comp.has_spoofing_defense():
                    return True
        return False
