from saci.modeling import CPV
from saci.modeling.device import Controller, Lidar, Motor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln


class LiDARShadowMaterialCPV(CPV):
    NAME = "Shadow Hack Materials Trigger False LiDAR Objects"

    def __init__(self):
        super().__init__(
            required_components=[
                Lidar(),
                Controller(),
                Motor(),
            ],
            entry_component=Lidar(),
            exit_component=Motor(),
            vulnerabilities=[LiDARSpoofingVuln()],
            initial_conditions={
                "Position": "CPS rover approaches an empty lane segment within",
                "Heading": "Aligned so the LiDAR scanning plane covers the roadway centerline",
                "Speed": "Any (>0)",
                "Environment": "Paved surface where reflective sheets can be laid flat with the ground",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Line-of-sight access to the roadway segment the CPS rover will traverse",
                "Mirror sheet or material with high reflectivity cut to the optimized trapezoid",
                "Low-profile weights/adhesive to keep the sheet flat so traffic does not shift it",
                "Ability to deploy and retrieve the sheet quickly",
            ],
            attack_vectors=[
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
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="False obstacle detection, leading to emergency braking",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Measuring shadow point clouds at practical distance range (closest ray hitting distance to critical bracking distance) from the LiDAR sensor"
                "Trapezoidal model includes a, b, l parameters that can be adjusted to fit the shadow point clouds"
                "Found the optimal parameters that can achieve the best false obstacle detection"
                "Report the parameters to TA2"
                "TA2 Exploit Steps",
                "Implement a simulation of environment inference such as the mirror sheet"
                "Run the simulation to analyze how the environment inference affects the operation of the CPS"
                "Report the findings to TA3"
                "TA3 Exploit Steps",
                "Place the mirror sheet on the roadway centerline so that it lies within the LiDAR fan"
                "Anchor the corners with low-profile tape or weights to keep the sheet flat"
                "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                "Start a mission for the rover and observe that it begins to drive.",
                "Observe that the rover is braking or maneuvering to avoid the false obstacle",
                "Verify the attack is successful",
                "Document the attack parameters and results",
            ],
            associated_files=["papers/usenixsecurity25-kobayashi.pdf"],
            reference_urls=[
                "https://www.usenix.org/conference/usenixsecurity25/presentation/kobayashi",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("LiDARShadowFalsePositive", True)
