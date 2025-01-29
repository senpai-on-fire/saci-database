from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Serial, Gyroscope, PWMChannel, ESC, MultiCopterMotor)
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.state import GlobalState

from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_emi_serial_shielding_vuln import LackEMISerialShieldingVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class GyroscopeEMIChannelDisruptionCPV(CPV):
    
    NAME = "Electromagnetic Interference (EMI) on Gyroscope Communication Channel"

    def __init__(self):
        super().__init__(
            required_components=[
                Gyroscope(),       
                Serial(),
                PX4Controller(),  
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),     
            ],
            entry_component=Serial(), 
            exit_component=MultiCopterMotor(),          

            vulnerabilities=[LackEMISerialShieldingVuln, ControllerIntegrityVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Proximity to EMI emitter",
                "RemoteController": "On",
                "CPSController": "Active",
                "OperatingMode": "Autonomous or Semi-Autonomous",
            },

            attack_requirements=[
                "High-power EMI emitter tuned to interfere with the gyroscope communication channel",
                "Proximity to the UAV's gyroscope or communication pathway",
                "Knowledge of the gyroscope's communication protocol and operating frequencies",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Electromagnetic Signals Interference", 
                    signal=MagneticAttackSignal(
                        src=ExternalInput(),
                        dst=Serial(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Inject electromagnetic interference into the gyroscope's communication channel",
                        "equipment": "High-power EMI emitter",
                        "target_frequency": "Specific to the gyroscope's communication protocol",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Disrupted gyroscope data leads to inaccurate flight paths and navigation failure."
                )
            ],

            exploit_steps=[
                "Identify the gyroscope's serial communication channel specifications, including protocol and frequency range.",
                "Prepare a high-power EMI emitter capable of interfering with the identified channel.",
                "Position the EMI emitter near the UAV, ensuring proximity to the gyroscope's communication pathway.",
                "Activate the EMI emitter to inject interference into the communication channel.",
                "Monitor the UAV for signs of flight instability or orientation errors caused by corrupted gyroscope data.",
            ],

            associated_files=[],
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state, such as flight instability or loss of navigation
        return state.has_property("FlightInstability", True) or state.has_property("NavigationFailure", True)
