from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Magnetometer, Serial, PWMChannel, ESC, MultiCopterMotor)
from saci_db.devices.px4_quadcopter_device import PX4Controller


from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.lack_emi_serial_shielding_vuln import LackEMISerialShieldingVuln
from saci_db.vulns.lack_emi_controller_shielding_vuln import LackEMIControllerShieldingVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput
from saci.modeling.device import Serial
from saci.modeling.state import GlobalState

class MagnetometerEMIChannelDisruptionCPV(CPV):

    NAME = "The EMI Spoofing Attack on Magnetometer Serial Communication Channel"

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

            vulnerabilities=[LackEMISerialShieldingVuln(), LackEMIControllerShieldingVuln(), ControllerIntegrityVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Proximity to EMI emitter ( 30W for 10cm, 300-500KW for 100 m)",
                "RemoteController": "On",
                "CPSController": "Active",
                "OperatingMode": "Manual or Mission",
            },

            attack_requirements=[
                "High-power EMI emitter tuned to interfere with the magnetometer communication channel",
                "Proximity to the CPS's controller or communication pathway",
                "Knowledge of the magnetometer's communication protocol and operating frequencies",
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
                        "attack_method": "Inject electromagnetic interference into the magnetometer's communication channel",
                        "equipment": "High-power EMI emitter (~30W for 10cm, ~300-500KW for 100 m)",
                        "target_frequency": "Specific to the controller used",
                    },
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Disrupted magnetometer data leads to incorrect flight paths and navigation errors"
                ),
            ],

            exploit_steps = [
                "TA1 Exploit Steps",
                    "Model the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                    "The model must include:",
                    "    - Controller attitude logic algorithm.",
                    "    - Magnetometer sensor outputs at the bit level.",
                    "    - Magnetometer-Controller communication channel at the bit level.",
                    "    - Any required physical parameters to simulate drone flight.",
                    "    - Electronic speed controller logic and output."
                    "    - CPS actuators (e.g., motors) controlled by the ESC.",

                "TA2 Exploit Steps",
                    "Simulate the impact of fault injection into the serial communication channel on the drone flight to verify the validity of the attack.",
                    "Start the simulation by allowing the drone to fly to a certain altitude and hover.",
                    "At arbitrary time x, start the fault injection into the magnetometer-controller communication channel and verify the attack impact.",
                    "This simulation does not need to include any ElectroMagnetic Interference (EMI); instead, force random bits to be transmitted throughout the simulation.",
                    "Report your findings to TA3.",
                    
                "TA3 Exploit Steps",
                    "Identify the magnetometer's serial communication channel protocol and transmission frequency.",
                    "Wait for TA2 to finish all their steps and receive their findings.",
                    "Identify the system's potential entry points and susceptible frequencies:",
                    "    - Tools and Equipment:",
                    "        + EMC scanner.",
                    "        + Spectrum analyzer.",
                    "    - Environment: Shielded chamber.",
                    "    - Ensure the following steps are done in a chamber shielded from any external sources of ElectroMagnetic Interference (EMI).",
                    "    - Connect the EMC scanner to the spectrum analyzer.",
                    "    - Turn on the drone system (without flying).",
                    "    - Scan the EMI radiated from the controller board together with the magnetometer using the EMC scanner.",
                    "    - The peaks in the spectrum represent susceptible frequencies, and the location on the board where the peak in the spectrum is observed is an entry point.",
                    "Choose the preferred susceptible frequency and entry point.",
                    "    - Tools and Equipment:",
                    "        + Antenna.",
                    "        + Function Generator.",
                    "        + Amplifier (at least 100mW, 30W preferred).",
                    "        + Oscilloscope.",
                    "        + Logic analyzer.",
                    "    - Environment: Any (shielded chamber if transmission power is high).",
                    "    - Locate the PX4 controller communication pins.",
                    "    - Connect the oscilloscope and the logic analyzer to the PX4 communication pins.",
                    "    - Place the antenna as close as possible to the controller board.",
                    "    - Connect the function generator to the amplifier and the amplifier to the antenna.",
                    "    - Turn on the oscilloscope and the logic analyzer.",
                    "    - Set the logic analyzer to a sampling rate much higher than the communication transmission frequency (at least 5 times, higher is preferable).",
                    "    - Turn on the drone system (without flying) and observe the nominal voltage values.",
                    "    - Turn on the function generator and set it to generate a sinusoidal signal at one of the susceptible frequencies.",
                    "    - Direct the antenna towards the respective entry point.",
                    "    - Slowly increase the amplifier's output power while monitoring the oscilloscope until a deviation from the nominal values is observed.",
                    "    - Monitor the logic analyzer and check if any bit flips have occurred (you should see instances of rapid bit flipping within the transmission period of a single bit).",
                    "    - If no bit flipping occurs, further increase the output power of the amplifier.",
                    "    - Repeat the four previous steps for each entry point.",
                    "    - Choose the preferred susceptible frequency and entry point to launch the attack (the one that required the least power).",
                    "Launch the attack.",
                    "    - Tools and Equipment:",
                    "        + Highly directional antenna.",
                    "        + Function Generator.",
                    "        + Amplifier.",
                    "        + Drone holding frame.",
                    "    - Install the drone into the holding frame and turn it on.",
                    "    - Set it to hover using the RC.",
                    "    - Connect the function generator, antenna, and amplifier.",
                    "    - Point the antenna towards the drone, no further than 50cm away from the drone.",
                    "    - Power on the amplifier and function generator and set it up to generate a sinusoidal signal at the chosen susceptible frequency.",
                    "    - Monitor the CPS for signs of flight instability or orientation errors caused by corrupted magnetometer data.",
            ],
            associated_files=[],
            reference_urls=[
                "https://www.ndss-symposium.org/wp-content/uploads/2023/02/ndss2023_f616_paper.pdf",
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # Define the goal state, such as heading disruption or navigation failure
        return state.has_property("HeadingDisruption", True) or state.has_property("NavigationFailure", True)
