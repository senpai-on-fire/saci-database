from saci.modeling import CPV
from saci.modeling.device import Controller, Lidar, Motor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack import OpticalAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.ml_adversarial_vuln import DeepNeuralNetworkVuln


class LiDARInvisibleVehicleCPV(CPV):
    NAME = "AE-Morpher Ornaments Hide Vehicles from LiDAR Detectors"

    def __init__(self):
        super().__init__(
            required_components=[
                Lidar(),
                Controller(),
                Motor(),
            ],
            entry_component=Lidar(),
            exit_component=Motor(),
            vulnerabilities=[DeepNeuralNetworkVuln()],
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
                "Physical access within LiDAR range (< 27 inches)",
                "Adversarial ornament (flat polygonal surfaces) attached to the target object",
                "Clear line-of-sight to LiDAR sensor",
                "Understanding of LiDAR detection threshold",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Adversarial 3D Mesh LiDAR Detection Bypass",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(),
                        dst=Lidar(),
                    ),
                    required_access_level="Physical",
                    configuration={
                        "object": "Folded polygonal ornament that replaces scattered adversarial vertices with flat faces",
                        "placement": "Attached to the target object",
                        "goal": "Fail to detect the object",
                        "effect": "Prevents the CPS from braking",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Control Hijacking",
                    description="Adversarial 3D mesh bypasses LiDAR detection, potentially leading to collisions.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Generate a digital adversarial object against the target LiDAR detector and obtain mesh vertices.",
                "Perform ray-cast simulations at multiple distances (effective distance range divided into N segments) to record which vertices remain effective.",
                "Report the findings to TA2",
                "TA2 Exploit Steps",
                "Implemment a simulation of environmental inference to expand effective vertex into flat adversarial faces (rectangular edge) sized to match the LiDAR’s angular spacing",
                "Connect faces into a folded surface to form a thin 3D ornament.",
                "Attach the ornament to the target object",
                "Vertify the attack is successful"
                "Document the attack parameters and results"
                "TA3 Exploit Steps",
                "Fabricate the ornament with cardboard/foam or 3D print it, then mount it on the roof or trunk of the target object.",
                "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                "Start a mission for the rover and observe that it begins to drive.",
                "Observe rover continues movement despite obstacle presence",
                "Verify rover fails to detect obstacle at expected distance",
                "Document attack success and system behavior",
                "Use emergency stop via web interface if needed",
                "Power off rover using hex wrench (clockwise rotation until LEDs off)",
            ],
            associated_files=[""],
            reference_urls=[
                "https://www.usenix.org/conference/usenixsecurity24/presentation/zhu-shenchen",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        return state.has_property("LiDARHiddenObjects", True)
