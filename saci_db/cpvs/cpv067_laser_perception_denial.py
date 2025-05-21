from saci.modeling import CPV
from saci.modeling.device import Camera, PX4Controller, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.optical_attack_signal import OpticalAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.vision_sensor_laser_vuln import VisionSensorLaserVuln

class LaserVisionAttackCPV(CPV):

    NAME = "Remote Laser-Based Attack on Drone Vision Sensors"

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
                VisionSensorLaserVuln(),
            ],

            goals=[
                "Disrupt the normal functioning of the drone's vision sensor",
                "Cause misperception or failure in obstacle avoidance and positioning",
            ],

            initial_conditions={
                "TargetSensor": "DJI drones with one camera and at least one pair of binocular sensors",
                "AttackTool": "Laser pointer (660-nm) with ~10000 lux intensity",
                "Environment": "Indoor and outdoor, 25-110 lux ambient brightness",
                "AttackDistance": "1.5m-5m",
                "AttackAngle": "0°, 30°, 60°",
            },

            attack_requirements=[
                "No physical access to the drone required",
                "No need to modify drone hardware or software",
                "Line-of-sight to the camera sensor must be maintained",
                "Drone operates autonomously and is out of operator's sight",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Laser Projection to Camera",
                    signal=OpticalAttackSignal(
                        src=ExternalInput(), dst=Camera(), modality="laser"
                    ),
                    required_access_level="Remote",
                    configuration={
                        "wavelength": "660 nm",
                        "intensity": "10000 lux",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Sensor Disruption",
                    description="Laser injection reduces perception accuracy or causes visual module to fail, impacting autonomous control."
                )
            ],

            exploit_steps=[
                "Align laser pointer with the drone's vision sensor from a distance (1.5-5m)",
                "Project continuous or pulsed beam into the camera's field of view",
                "Camera experiences saturation or false image patterns",
                "Obstacle avoidance or positioning algorithms receive corrupted input",
                "Drone exhibits unstable flight, drift, or collision behavior",
            ],

            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=9444889"
            ]
        )

        self.goal_state = [{"VisionSystem": "Disrupted"}]

    def in_goal_state(self, state):
        return state.get("VisionSystem") == "Disrupted"
