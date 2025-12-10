from saci.modeling import CPV
from saci.modeling.device import Camera, Controller, Lidar, Motor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln
from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln


class LiDARCameraFusionSpoofingCPV(CPV):
    NAME = "Frustum Aligned LiDAR Spoofing Camera/LiDAR Fusion"

    def __init__(self):
        super().__init__(
            required_components=[
                Lidar(),
                Camera(),
                Controller(),
                Motor(),
            ],
            entry_component=Lidar(),
            exit_component=Motor(),
            vulnerabilities=[LiDARSpoofingVuln(), DeepNeuralNetworkVuln()],
            initial_conditions={
                "Position": "CPS rover shares a lane with a target obstacle within perception range",
                "Heading": "Aligned with the lane so camera and LiDAR observe the same frustum",
                "Speed": "Any (>0)",
                "Environment": "Indoor or controlled outdoor",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Line-of-sight access to LiDAR receiver",
                "IR laser source",
                "Stable laser orientation within LiDAR FOV",
                "Knowledge of LiDAR detection threshold",
            ],
            attack_vectors=[
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
                ),
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="Spoofed frustum points cause the fusion DNN to trust nonexistent obstacles or ignore real ones, leading to abrupt braking or collisions.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Collect synchronized LiDAR/camera logs for the mission route and identify bounding boxes that define the victim's frustums.",
                "Replay the fusion stack offline to catalog points-per-frame and range combinations",
                "   - Use spoof parameters such as ni (2‑200 injected points) and di (offsets from r0−10 m to r0+30 m, where r0 is the target original range) to find combinations that lead to FP or FN",
                "Report the findings to TA2",
                "TA2 Exploit Steps",
                "Prototype the fusion stack in simulation,"
                "Perform frustum attack using the findings from TA1"
                "TA3 Exploit Steps",
                "Mount the LiDAR spoofer on a target object or infrastructure in-line with the CPS lane.",
                "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                "Start a mission for the rover and observe that it begins to drive.",
                "Use delay modulation to inject the precomputed clusters while monitoring the rover's perception for FP/FN detection",
                "Maintain the sequence for a sufficient time to force the rover's tracker to build an adversarial trajectory, then observe emergency braking or collision with the hidden target.",
                "Vertify the attack is successful"
            ],
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/conference/usenixsecurity22/presentation/hallyburton",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("MSFFrustumSpoofed", True)
