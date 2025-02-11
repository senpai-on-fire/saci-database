from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Serial, Accelerometer, PWMChannel, ESC, MultiCopterMotor)
from saci_db.devices.px4_quadcopter_device import PX4Controller
from saci.modeling.device import Serial
from saci.modeling.state import GlobalState

from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_emi_serial_shielding_vuln import LackEMISerialShieldingVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput


class AccelerometerEMIChannelDisruptionCPV(CPV):
    
    NAME = "The EMI Spoofing Attack on Accelerometer Serial Communication Channel"

    def __init__(self):
        super().__init__(
            required_components=[
                Accelerometer(),   
                Serial(),
                PX4Controller(),    
                PWMChannel(),
                ESC(),
                MultiCopterMotor(),     
            ],
            entry_component=Serial(), 
            exit_component=MultiCopterMotor(),          

            vulnerabilities=[LackEMISerialShieldingVuln, LackEMIControllerShieldingVuln(), ControllerIntegrityVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Proximity to EMI emitter (~30W for 10cm, ~300-500KW for 100 m)",
                "RemoteController": "On",
                "CPSController": "Active",
                "OperatingMode": "Autonomous or Semi-Autonomous",
            },

            attack_requirements=[
                "High-power EMI emitter tuned to interfere with the accelerometer communication channel",
                "Proximity to the UAV's controller or communication pathway",
                "Knowledge of the accelerometer's communication protocol and operating frequencies",
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Electromagnetic Signals Interference", 
                    signal=MagneticAttackSignal(
                        src=ExternalInput(),
                        dst=PX4Controller(),
                    ),
                    required_access_level="Proximity",
                    configuration={
                        "attack_method": "Inject electromagnetic interference into the accelerometer's communication channel",
                        "equipment": "High-power EMI emitter (~30W for 10cm, ~300-500KW for 100 m)",
                        "target_frequency": "Specific to the controller used",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Disrupted accelerometer data leads to inaccurate motion detection and navigation errors."
                )
            ],

            exploit_steps=[
                "* Wait for TA3 to finish step 3 and receive their findings",
                "TA1-1) Simulate the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack",
                "   - The simulation model must include:",
                "       + Controller attitude logic algorithm",
                "       + Accelerometer sensor outputs at bit level",
                "       + Accelerometer-Controller communication channel at bit level",
                "       + Any required physical parameters to simulate drone flight",
                "       + Electronic speed controller logic and output",
                "   - Start the simulation by letting the drone fly to a certain altitude and hover",
                "   - At arbitrary time x start the fault injection into the accelerometer-controller communication channel and verify the attack impact",
                "   - This simulation does not need to include any ElectroMagnetic Interference (EMI) you just force the random bits transmitted the communication channel random throught the simulation",
                "TA1-2) Report your findings to TA3",
                "--------------------------------------------------------",
                "TA3-1) Record all drone physical properties. These include",
                "   - Weight",
                "   - Dimensions",
                "   - Center of gravity",
                "   - Propeller size",
                "   - Number of propellers",
                "   - Blade shape & pitch",
                "   - Number of blades per propeller",
                "TA3-2) Use Optical imaging tools to catalog all components of the drone system.",
                "TA3-3) Identify the accelerometer's serial communication channel protocol and transmission frequency",
                "* Wait for TA1 to finish all their steps and receive their findings",
                "TA3-4) Identify the system's potential entry points and susceptible frequencies:",
                "   - Tools and Equipment:",
                "       + EMC",
                "       + Spectrum analyzer",
                "   - Environment: shielded chamber",
                "   - Make sure the following steps are done in a chamber shielded from any external sources ElectroMagentic Interference (EMI)",
                "   - Connect the EMC to the spectrum analyzer",
                "   - Turn on the drone system (without flying)",
                "   - Scan the EMI radiated from the controller board together with the accelerometer using the EMC scanner",
                "   - The peaks in the spectrum represent susceptible frequencies and the location on the board where the peak in the spectrum is observed is an entry point",
                "TA3-5) Choose the preferred susceptible frequency and entry point",
                "   - Tools and Equipment:",
                "       + Antenna",
                "       + Function Generator",
                "       + Amplifier (at least 100 mw, 30 W preferred)",
                "       + Oscilloscope",
                "       + Logic analyzer", 
                "   - Environment: Any (shielded chamber if transmission power is high)",
                "   - Locate the PX4 controller communication pins",
                "   - Connect the oscilloscope and the logic analyzer to the PX4 communication pins",
                "   - Place the antenna as close as possible to the controller board",
                "   - Connect the function generator to the amplifier and the amplifier to the antenna",
                "   - Turn on the oscilloscope and the logic analyzer",
                "   - Set the logic analyzer to a sampling rate much higher than the communication transmission frequency (at least 5 times, higher is preferable)",
                "   - Turn on the drone system (without flying) and observe the nominal voltage values",
                "   - Turn on the function generator and set it up to generate a sinusoidal at one of the susceptible frequencies",
                "   - Direct the antenna towards the respective entry point",
                "   - Slowly increase the amplifier's output power while keeping an eye on the oscilloscope until a deviation from the nominal values is observed",
                "   - Monitor the logic analyzer and check if any bit flips have occurred (You should see instances of rapid bit flipping within the transmission period of a single bit)",
                "   - If no bit flipping occurred further increase the output power of the amplifier.",
                "   - Repeat the four previous steps for each entry point",
                "   - Choose the preferred susceptible frequency and entry point to launch the attack (The one that needed the least power)",
                "   - This table could serve as a guideline to the expected power required for some controllers",
                "     +=========================+==========+==========+=====================================+",
                "     |       Controller        |  Power   | Distance | Induced voltage / Transmitted power |",
                "     +=========================+==========+==========+=====================================+",
                "     | Arduino Uno, Nano, Mega | 100 mW   | 10 cm    |                                     |",
                "     +-------------------------+----------+----------+-------------------------------------+",
                "     | Pixhawk4                | 12.6 W   | 10 cm    |                                     |",
                "     +-------------------------+----------+----------+           0.10152 V/3dBm            +",
                "     | Pixhawk4                | 100 W    | 50 cm    |                                     |",
                "     +-------------------------+----------+----------+-------------------------------------+",
                "     | DJI                     | 30.357 W | 10 cm    |           0.1128 V/3dBm             |",
                "     +-------------------------+----------+----------+-------------------------------------+",
                "TA3-6) Launch the attack",
                "   - Tools and Equipment:",
                "       + Highly directional antenna",
                "       + Function Generator",
                "       + Amplifier",
                "       + Drone holding frame",
                "   - Install the drone into the holding frame and turn it on",
                "   - Set it to hover using the RC",
                "   - Connect the function generator, antenna and amplifier",
                "   - Point the antenna towards the drone, no further than 50cm away from the drone",
                "   - Power on the amplifier and function generator and set it up to generate a sinusoidal and the chosen susceptible frequency",
                "   - Set up the function generator to generate a sinusoidal at the chosen susceptible frequency",
                "   - Monitor the UAV for signs of flight instability or orientation errors caused by corrupted accelerometer data."
            ],

            associated_files=[],
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state, such as flight instability or navigation disruption
        return state.has_property("FlightInstability", True) or state.has_property("NavigationDisruption", True)
