import os
from clorm import Predicate

from saci.modeling.vulnerability import PublicSecretVulnerability
from saci.modeling.device import Device, Lidar
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
            component=Lidar(),
            _input=UnauthenticatedCommunication(src=ExternalInput()),
            output=UnauthenticatedCommunication(),
            attack_ASP=LiDARSpoofingPred,
            rulefile=os.path.join(os.path.dirname(os.path.realpath(__file__)), "lidar_spoofing.lp"),
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
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": "IR laser injection, Pulse timing manipulation",
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
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": "Signal redirection, Distance manipulation",
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
                            name="Reflective Object Injection",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "objects": "Commercial drones or arbitrary reflective boards",
                                "placement": "Adversarial coordinates near target object",
                                "goal": "Hide the target object from LiDAR perception",
                                "effect": "Hide target object detection",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARArbitraryObjectCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                            description="Injected reflective clusters hide the objects the CPS is following, potentially leading to incorrect navigation decisions",
                        )
                    ],
                    "exploit_steps": [
                        "Collect surrogate LiDAR scans of the CPS route to model the target object contour.",
                        "Run the Location Probing algorithm to obtain adversarial coordinates.",
                        "Position reflective drones/boards at the adversarial coordinates.",
                        "Confirm detection bypass.",
                    ],
                    "reference_urls": [
                        "https://doi.org/10.1145/3460120.3485377",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Frustum Attack",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": "Pattern injection, Pulse relay spoofing",
                                "modality": "Laser pulses",
                                "wavelength": "850nm",
                                "injection_region": "Frustum region of the target obstacle",
                                "target_effect": "False obstacle detection (FP) or obstacle removal (FN)",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARCameraFusionSpoofingCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                           description="Spoofed frustum points cause the fusion DNN to trust nonexistent obstacles or ignore real ones, leading to abrupt braking or collisions.",
                        )
                    ],
                    "exploit_steps": [
                        "Collect synchronized LiDAR/camera logs for the mission route and identify bounding boxes that define the victim's frustums.",
                        "Replay the fusion stack offline to catalog spoof parameters (points per frame, range offsets) that consistently produce FP or FN outcomes.",
                        "Perform frustum attack following the combinations.",
                        "Confirm FP/FN detection.",
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Adversarial Shadow Sheet",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "object": "Highly reflective mirror sheet aligned with the lane to reflect the LiDAR pulse away and make a false shadow region",
                                "placement": "Lay the trapezoid flat on the lane center so LiDAR rays between strike it before the ground",
                                "goal": "Remove returns inside the sheet so the detector hallucinate an object where only a shadow exists",
                                "effect": "False obstacle detection, leading to emergency braking",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARShadowMaterialCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                           description="False obstacle detection, leading to emergency braking",
                        )
                    ],
                    "exploit_steps": [
                        "Measuring shadow point clouds at practical distance range (closest ray hitting distance to critical bracking distance) from the LiDAR sensor",
                        "Optimize the trapezoidal model parameters to fit the shadow point clouds",
                        "Place the optimized trapezoidal model with reflective material and perform the attack",
                        "Confirm false obstacle detection and emergency braking",
                    ],
                    "reference_urls": [
                        "https://www.usenix.org/conference/usenixsecurity25/presentation/kobayashi",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="Trajectory Spoofing Objects",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "object": "Two lightweight planar boards to inject LiDAR points that skew the target’s bounding box",
                                "placement": "Boards arranged within a search region around the target object at the chosen attack point",
                                "goal": "Incorrect trajectory prediction",
                                "effect": "Incorrect trajectory prediction, leading to emergency braking or hazardous maneuvers",
                            },
                        )
                    ],
                    "related_cpv": ["LiDARTrajectoryPredictionManipulationCPV"],
                    "comp_attack_effect": [
                        BaseCompEffect(
                            category="Control Hijacking",
                           description="The CPS believes a parked object will move into its lane, triggering sudden braking or maneuvers that can cause collisions.",
                        )
                    ],
                    "exploit_steps": [
                        "Find state perturbation set Cst (lateral shift, longitudinal shift, rotation angle) that can mislead the prediction model under certain frame",
                        "Minimize the distance between two trajectories, leading to an intersecting trajectory",
                        "Find the adversarial locations for placing common objects that can achieve the found state perturbations",
                        "Mount the planar boards at the computed coordinates (side or front corridors) and align them toward the rover’s LiDAR."
                        "Confirm incorrect trajectory prediction that leads to emergency braking or hazardous maneuvers"
                    ],
                    "reference_urls": [
                        "https://arxiv.org/abs/2406.11707",
                    ],
                },
                {
                    "attack_vector": [
                        BaseAttackVector(
                            name="LiDAR Sensor Denial Attack",
                            signal=OpticalAttackSignal(
                                src=ExternalInput(),
                                dst=Lidar(),
                            ),
                            required_access_level="Physical",
                            configuration={
                                "methods": "LED flooding, Pulse replay",
                                "modality": "Visible/IR light, Recorded pulses",
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
                    "attack_vector": [EnvironmentalInterference(dst=Lidar(), modality="non-reflective material")],
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
            if isinstance(comp, Lidar):
                if not comp.has_signal_validation():
                    return True
        return False
