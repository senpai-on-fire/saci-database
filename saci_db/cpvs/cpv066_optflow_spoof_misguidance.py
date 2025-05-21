from saci.modeling import CPV
from saci.modeling.device import Camera, PX4Controller, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.opticalflow_spoofing_vuln import OpticalFlowSpoofingVuln

class CPV066_OptflowSpoofMisguidance(CPV):

    NAME = "CPV066: Optical Flow Spoofing to Misguide UAV Motion"

    def __init__(self):
        super().__init__(
            required_components=[
                Camera(),
                PX4Controller(),
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),
            ],

            entry_component=Camera(),
            exit_component=MultiCopterMotor(),

            vulnerabilities=[
                OpticalFlowSpoofingVuln(),
            ],

            goals=[
                "Inject misleading optical flow to manipulate UAV movement",
            ],

            initial_conditions={
                "TargetSensor": "Downward-facing optical flow sensor using Lucas-Kanade method",
                "Environment": "Indoor and outdoor flat surfaces (tile, concrete, carpet)",
                "AttackerPosition": "Ground level, within 3-10 feet of UAV",
                "AttackTool": "Laser pointer with grid lens or pocket projector",
                "FlightMode": "Loiter / Position Hold",
            },

            attack_requirements=[
                "Target platform relies on visual motion estimation for position stabilization",
                "Attacker can influence the visual input by injecting patterns into the sensor's field of view",
                "No system-level access or modification to onboard hardware or software is required",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Optical Flow Light Pattern Injection",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=Camera(), modality="light"
                    ),
                    required_access_level="Physical",
                    configuration={
                        "pattern_type": "Dynamic grid or dot projection",
                        "tool": "Laser grid / Pico projector",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Sensor Spoofing",
                    description="UAV misinterprets optical flow and drifts or alters course in response to false motion cues."
                )
            ],

            exploit_steps=[
                "Prepare spoofing device (laser grid or projector) near UAV test area",
                "Wait for UAV to enter loiter mode using optical flow",
                "Project dynamic light pattern into camera field-of-view",
                "Induce perceived motion through modulation of the pattern",
                "Observe lateral movement or course deviation in UAV",
            ],

            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf"
            ]
        )

        self.goal_state = [{"UAVDrift": "Induced"}]

    def in_goal_state(self, state):
        return state.get("UAVDrift") == "Induced"
