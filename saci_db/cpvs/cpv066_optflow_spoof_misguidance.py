from saci.modeling import CPV
from saci.modeling.device import (
    Camera,
    OpticalFlowSensor,
    Controller,
    Motor,
)
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
                OpticalFlowSensor(), # This is the entry component (Required)
                # Serial(), # Removed considering that the OpticalFlowSensor is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Camera(),
            exit_component=Motor(),
            
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
                    description="UAV misinterprets optical flow and drifts or alters course in response to false motion cues.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Implement a Model to simulate the optical flow spoofing attack",
                    "The model must include:",
                    "    - Lucas-Kanade optical flow algorithm simulation",
                    "    - Light pattern generation and modulation",
                    "    - UAV motion response simulation",
                "TA2 Exploit Steps",
                    "Simulate the spoofing attack and its effects",
                    "The simulation must include:",
                    "    - Pattern optimization for different surfaces",
                    "    - Light intensity and pattern speed analysis",
                    "    - Impact analysis on UAV drift behavior",
                "TA3 Exploit Steps",
                    "Execute the physical attack in real environment",
                    "Set up laser grid or pocket projector near UAV",
                    "Position device within 3-10 feet of UAV",
                    "Wait for UAV to enter loiter/position hold mode",
                    "Project dynamic light pattern into camera field-of-view",
                    "Modulate pattern to induce perceived motion",
                    "Monitor and verify UAV drift response",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://www.usenix.org/system/files/conference/woot16/woot16-paper-davidson.pdf"
            ],
        )

        self.goal_state = [{"UAVDrift": "Induced"}]

    def in_goal_state(self, state):
        return state.get("UAVDrift") == "Induced"
