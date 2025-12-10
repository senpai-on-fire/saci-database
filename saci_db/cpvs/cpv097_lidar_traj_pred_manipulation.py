from saci.modeling import CPV
from saci.modeling.device import Controller, Lidar, Motor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln


class LiDARTrajectoryPredictionManipulationCPV(CPV):
    NAME = "LiDAR-Induced Trajectory Prediction Manipulation"

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
                "Position": "CPS rover shares a lane with a parked/slow vehicle within 5–25 m",
                "Heading": "Aligned so the target stays inside the LiDAR field-of-view as the rover advances",
                "Speed": "Any (>0); prediction stack samples ≥5 historical frames",
                "Environment": "Roadway or test lane where adversarial objects can be staged around the target",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Line-of-sight access to the victim LiDAR and the parked/slow target vehicle",
                "Locations along the lane shoulder where planar boards or billboards can be staged safely",
                "Lightweight cardboard/foam boards on tripods that can be tilted toward the LiDAR",
                "Ability to approach, deploy, and retrieve the boards within minutes without alerting the rover operator",
            ],
            attack_vectors=[
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
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="The CPS believes a parked object will move into its lane, triggering sudden braking or maneuvers that can cause collisions.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Find state perturbation set Cst (lateral shift, longitudinal shift, rotation angle) that can mislead the prediction model under certain frame"
                "Minimize the distance between two trajectories, leading to an intersecting trajectory"
                "Find the adversarial locations for placing common objects that can achieve the found state perturbations"
                "Report the findings to TA2"
                "Setup simulation environment and setup the attack by placing the common objects at the computed coordinates"
                "Perform the attack and verify the impact"
                "Report the findings to TA3"
                "TA3 Exploit Steps",
                "Mount the planar boards at the computed coordinates (side or front corridors) and align them toward the rover’s LiDAR.",
                "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                "Start a mission for the rover and observe that it begins to drive.",
                "Observe the rover's trajectory and verify it is incorrect",
                "Verify the rover is braking or maneuvering to avoid the collision",
                "Use emergency stop via web interface if needed",
                "Power off rover using hex wrench (clockwise rotation until LEDs off)",
                "Document attack success and system behavior",
            ],
            associated_files=[],
            reference_urls=[
                "https://arxiv.org/abs/2406.11707",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("TrajectoryPredictionManipulated", True)
