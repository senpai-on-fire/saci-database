from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.environmental_attack_signal import EnvironmentalInterference
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.barometer_spoofing_vuln import BarometerSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import Barometer, Serial, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

class BarometricSensorSpoofingCPV(CPV):
    NAME = "Barometric Sensor Spoofing Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Barometer(),       
                Serial(),            
                PX4Controller(),   
                PWMChannel(),  
                ESC(),
                MultiCopterMotor(),
            ],
            entry_component=Barometer(),  
            exit_component=MultiCopterMotor(),  

            vulnerabilities=[BarometerSpoofingVuln(), ControllerIntegrityVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Controlled or with pressure manipulation capability",
                "RemoteController": "On",
                "CPSController": "Active",
                "Operating mode": "Autonomous or Semi-Autonomous",
            },

            attack_requirements=[
                "Compressed air source (e.g., air blower or air cannon)",
                "Proximity to the drone's barometric sensor",
                "Knowledge of barometric sensor location on the UAV",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Barometric Sensor Spoofing",
                    signal=EnvironmentalInterference(
                        src=ExternalInput(),
                        dst=Barometer(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Manipulating air pressure near the barometric sensor",
                        "equipment": "Compressed air source",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Causes the UAV to perceive incorrect altitude, leading to unstable or unintended flight behavior."
                )
            ],

            exploit_steps=[
                "Identify the location of the barometric sensor on the UAV.",
                "Position a compressed air source (e.g., air blower) close to the barometric sensor.",
                "Generate bursts of air pressure to create localized changes near the sensor.",
                "Monitor the UAV's response to verify that incorrect altitude readings are influencing its flight behavior.",
            ],

            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/document/8802817"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as altitude miscalculation or instability
        return state.has_property("AltitudeMiscalculation", True)
