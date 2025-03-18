from typing import List, Type

from saci.modeling import CPV
from saci.modeling.communication import ExternalInput

from saci.modeling.attack.environmental_attack_signal import EnvironmentalInterference
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci_db.vulns.barometer_spoofing_vuln import BarometerSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci_db.devices.ardupilot_quadcopter_device import ArduPilotController
from saci.modeling.device import Barometer, Serial, PWMChannel, ESC, MultiCopterMotor
from saci.modeling.state import GlobalState

class BarometricSensorSpoofingCPV(CPV):

    NAME = "The Acoustic Spoofing Attack on Barometric Sensors"

    def __init__(self):
        super().__init__(
            required_components=[
                Barometer(),       
                Serial(),            
                ArduPilotController(), 
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
                "OperatingMode": "Autonomous or Semi-autonomous",
            },

            attack_requirements=[
                "Strong Speaker",
                "Proximity to the CPS's barometric sensor",
                "Knowledge of barometric sensor location on the CPS",
                "Knowledge of the CPS navigation algorithm",
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
                        "attack_method": "Tampering with sensor output using audio signals",
                        "equipment": "Very load speaker (100dB)",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Causes the CPS to perceive incorrect altitude, leading to unstable or unintended flight behavior or leading the CPS to an incorrect location if used in conjunction with other sensors"
                )
            ],

            exploit_steps= [
                "TA1 Exploit Steps",
                "   - Use the navigation planning model made by TA3 to simulate the path planning while feeding it sensor inputs with some added error",
                "   - Try different faulty input combinations for the different available sensors and detect the maximum possible amount of errors inducible in the sensor reading without triggering the data integrity check.",
                "   - Report your findings to TA3",
                "   - Wait for the error generator model to be provided by TA3.",
                "   - Simulate the navigation planning model together with the error generator and verify the effectiveness of the attack.",
                "   - Report your findings to TA3",
        
                "TA2 Exploit Steps",
                "   - Reverse engineer the navigation system path planning algorithm, specifically, the altitude control. ",
                "   - Verify if the controller checks for data integrity, if so extract the data integrity check algorithm.",
                "   - Report your findings to TA3",
        
                "TA3 Exploit Steps",
                "   - Verify whether the CPS uses a barometer or not.",
                "   - Detect the type of controller and barometer used in the CPS",
                "   - Model the controller path planning and altitude control algorithms (Use TA2 findings)",
                "      - The model must include the controller data integrity detection algorithms.",
                "      - Model inputs:",
                "         - Start position",
                "         - Target destination",
                "         - Sensor readings at each time step including :",
                "            - Barometer",
                "            - GPS",
                "            - Accelerometer",
                "            - Gyroscope",
                "            - Any other sensors used to determine current CPS state (position, altitude, speed)",
                "      - Model output",
                "         - The 3D path to take at each time step, including the velocity and acceleration.",
                "   - Pass the model to TA1",
                "   - If the CPS uses a Kalman Filter (KF) based position estimation system, then model the phase 3 algorithm described in the fourth section of the 1st reference. Otherwise, a new algorithm with the following description is required:",
                "      - Inputs",
                "         - CPS current position",
                "         - CPS normal target destination",
                "         - CPS malicious target destination",
                "         - Allowable induced error combinations and limits that would not trigger integrity check (should be reported by TA1)",
                "      - Output",
                "         -  Series of errors to induce into sensor readings to reach the malicious destination",
                "   - Pass that model to TA1",
                "   - Wait for TA1 to verify the impact of the attack",
                "   - If possible, isolate the barometer sensor",
                "   - Detect the resonance frequencies of the barometer",
                "      - Tools and equipment",
                "         - Hearing Personal Protective Equipment (PPE)",
                "         - Loud directional speaker ( 100dB )",
                "         - Function generator, or a music player compatible with the speaker",
                "         - Oscilloscope if sensor output is analog, otherwise a logic analyzer or a PC interfaced with the sensor",
                "      - Environment",
                "         - Acoustically isolated chamber",
                "      - Steps",
                "         - Make sure the barometer sensor is stationary",
                "         - Make sure that the speaker and sensor are not mechanically coupled",
                "         - Wear any necessary PPEs",
                "         - Turn on the speaker and do a frequency sweep (1k to 30k) with a reasonable step (~50-100 Hz) while recording the sensor outputs",
                "         - Record the resonance frequencies where a deviation in the readings occurred.",
                "      - Design the audio signal that would induce the desired error ( Refer to the second reference. It is used for a gyroscope and accelerometer but same principals can apply to barometer)",
                "      - Go back to the same environment setup and play the designed signal and observe the navigation system state, verifying its disorientation",
            ],

            associated_files=[],
            reference_urls=[
                "https://ieeexplore.ieee.org/document/8802817",
                "https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=7961948"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state conditions, such as altitude miscalculation or instability
        return state.has_property("AltitudeMiscalculation", True)
