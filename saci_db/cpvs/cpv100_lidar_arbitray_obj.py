from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Lidar,
    Motor,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.lidar_spoofing_vuln import LiDARSpoofingVuln


class LiDARArbitraryObjectCPV(CPV):
    NAME = "Arbitrary Reflective Objects Hide Obstacles from LiDAR Perception"

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
                "Position": "CPS follows a mission waypoint with a tracked object ahead",
                "Heading": "Aligned with the planned path and unobstructed line-of-sight",
                "Speed": "Any (>0)",
                "Environment": "Indoor or controlled outdoor",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },
            attack_requirements=[
                "Surrogate LiDAR scans or dataset that reproduces the CPS mission route and target geometry",
                "Ability to query or replay the LiDAR perception stack to observe detection confidence",
                "Optimization tooling to find critical adversarial coordinates",
                "Two reflective drones/boards sized similar to quadcopters that can hover within ±0.2 m of the target coordinates",
            ],
            attack_vectors=[
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
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="Injected reflective clusters hide the objects the CPS is following, potentially leading to incorrect navigation decisions",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Collect surrogate LiDAR scans around the mission route using a sensor comparable to the CPS payload",
                "Run the Location Probing algorithm to rank candidate regions near the tracked obstacle's contour",
                "Solve the adversarial location optimization (Eq. (1)) to minimize the number of insertion points while pushing detection confidence below threshold",
                "Report to TA2 any required physical parameters to simulate the CPS dynamics and attacks",
                "TA2 Exploit Steps",
                "Implement a simulation of environmental inference to include the attack deployment and impact on the CPS",
                "Run the simulation to test various adversarial coordinates",
                "Validate detection threshold bypass conditions",
                "Document successful attack parameters",
                "TA3 Exploit Steps",
                "Using hex wrench, rotate power block counter-clockwise to power on rover",
                "Wait for system LEDs to light up",
                "Press button on power block to remove safety",
                "Connect to 'Arduino Wifi' network using password 'TSWIZZLE1989'",
                "Navigate to http://10.0.0.1/ in web browser",
                "Verify web interface shows 'START LEFT TURN' and 'START RIGHT TURN' buttons",
                "Press either button to initiate rover movement",
                'Test baseline obstacle detection by placing object (>= LiDAR height) within 27" of sensor',
                "Verify rover stops automatically",
                "Power off rover by rotating power block clockwise until LEDs turn off",
                "Repeat power-on sequence and initiate rover movement",
                "Place actual target object"
                "Command the drones/boards to hover at the adversarial coordinates",
                "Observe rover failing to detect the target object and maintaining its commanded speed",
                "Document attack success and system behavior",
                "Use emergency stop via web interface if needed",
                "Power off rover using hex wrench (clockwise rotation until LEDs off)",
            ],
            associated_files=[],
            reference_urls=[
                "https://doi.org/10.1145/3460120.3485377",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("LiDARHiddenObjects", True)
