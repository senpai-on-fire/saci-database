from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.magnetometer_spoofing_vuln import MagnetometerSpoofingVuln
from saci_db.vulns.lack_emi_sensor_shielding_vuln import LackEMISensorShieldingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import Serial, Magnetometer, PWMChannel, ESC, MultiCopterMotor, Telemetry
from saci.modeling.state import GlobalState

class EMISpoofingMagnetometerCPV(CPV):

    NAME = "The EMI Spoofing Attack on Magnetometer Sensors"

    def __init__(self):
        super().__init__(
            required_components=[
                Magnetometer(), 
                Serial(),
                PX4Controller(),    
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),   
            ],
            entry_component=Magnetometer(),   
            exit_component=MultiCopterMotor(),    

            vulnerabilities=[MagnetometerSpoofingVuln(), LackEMISensorShieldingVuln(), ControllerIntegrityVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any (>0)",
                "Environment": "Proximity to EMI source",
                "RemoteController": "On",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },


            attack_requirements=[
                "High-power EMI emitter capable of generating magnetic field interference",
                "Proximity to the CPS or line-of-sight to its magnetometer sensor",
                "Knowledge of the magnetometer sensor's operating characteristics",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Electromagnetic Signals Interference", 
                    signal=MagneticAttackSignal(
                        src=ExternalInput(),
                        dst=Magnetometer(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Emit electromagnetic interference targeting the magnetometer sensor",
                        "equipment": "High-power EMI emitter",
                        "target_frequency": "Specific to the magnetometer sensor's sensitivity range",
                    },
                )
            ],


            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Causes the CPS to miscalculate its heading due to corrupted magnetometer data."
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Model the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                            "The model must include:",
                            "    - Controller attitude logic algorithm.",
                            "    - Magnetoemter sensor outputs at the bit level.",
                            "    - Any required physical parameters to simulate CPS operation.",
                            "    - Electronic speed controller logic and output.",
                            "    - CPS actuators (e.g., motors) controlled by the ESC.",
                
                "TA2 Exploit Steps",
                    "Simulate the impact of fault injection into the magnetometer sensor readings.",
                    "At arbitrary time x, start the fault injection into the magnetometer sensor and verify the attack impact.",
                    "This simulation does not need to include any ElectroMagnetic Interference (EMI); instead, force random bits to be transmitted throughout the simulation.",
                    "Report your findings to TA3.",
                
                "TA3 Exploit Steps",
                    "Identify the operating characteristics and sensitivity range of the CPS's magnetometer sensor.",
                    "Acquire or construct a high-power EMI emitter capable of generating interference within the identified sensitivity range.",
                    "Position the EMI emitter in proximity to the CPS, ensuring line-of-sight to the magnetometer sensor.",
                    "Activate the EMI emitter to introduce interference, corrupting the magnetometer sensor's readings.",
                    "Monitor the CPS's behavior for signs of orientation miscalculation or navigation errors.",
            ],

            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/document/9245834"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state, such as orientation estimation error or navigation disruption
        return state.has_property("OrientationEstimationError", True) or state.has_property("NavigationDisruption", True)