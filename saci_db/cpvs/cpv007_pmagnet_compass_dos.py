from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Serial, Controller, PWMChannel, Motor, Serial, CANBus, CANTransceiver, CANShield)
from saci.modeling.device.sensor import CompassSensor
from saci.modeling.device.motor.steering import Steering
from saci.modeling.state import GlobalState

from saci_db.vulns.compass_spoofing_vuln import CompassSpoofingVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.magnetic_attack_signal import MagneticAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class CompassPermanentSpoofingCPV(CPV):
    
    NAME = "The Permanent Magnetic Interference on Compass"
    
    def __init__(self):
        super().__init__(
            required_components=[
                CompassSensor(),
                Serial(),
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),
                Controller(),
                PWMChannel(),
                Steering(),],
            entry_component=CompassSensor(),
            exit_component=Motor(),
            
            vulnerabilities=[CompassSpoofingVuln(), ControllerIntegrityVuln()],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any", 
                "Environment": "Any", 
                "RemoteController": "On", 
                "CPSController": "Moving",
                "Operating mode": "Mission",
                },

            attack_requirements = ["Magnet with adequate shapes and dimensions"],
            attack_vectors = [BaseAttackVector(name="Magnetic Signals Interference", 
                                               signal=MagneticAttackSignal(src=ExternalInput(), dst=CompassSensor()),
                                               required_access_level="Physical",
                                               configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='CPS drives in circles without stopping')],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "Reverse engineering the extracted firmware using a combination of standard software reverse engineering tools and Binsync.",
                    "Provide context for what the firmware is supposed to do when interacting with sensors (e.g., compass).",
                    "Check if the firmware accepts inputs from the compass sensor.",
                    "Identify the code that is implementing the CPS heading calculation from the compass.",
                    "Check if the code implements any filtering mechanism for compass readings.",
                    "Create models for the following components: Compass, CPS control logic, ESC logic and output, CPS actuators (e.g., motors) controlled by the ESC.",
                    "Report to TA2 any required physical parameters to simulate the CPS dynamics"

                "TA2 Exploit Steps",
                    "Simulate the impact of permanent heading mis-calculation on the CPS dynamics",
                    "Start the simulation by turning-on the CPS.",
                    "At arbitrary time x, start injecting errors into the compass sensor for y seconds",
                    "Change the orientation of the CPS in the simulation and observe the impact on the compass readings",
                    "Report the findings to TA3 to conduct the experiments on the physical CPS device",

                "TA3 Exploit Steps",
                    "Use Optical imaging tools to catalog all of the components on the CPS.",
                    "Identify which components contained memory that might contain firmware.",
                    "Extract the firmware from the memory component.",
                    "Check if there is a compass (magnetometer) component.",
                    "Prepare a powerful magnet with adequate shapes and dimensions.",
                    "Install the magnet on top of the compass.",
                    "Until observing change in the compass readings, keep doing the following: Point the CPS device at a different direction then install the magnet on top of the compass.",
                    "Rotate the CPS device and observe that the compass readings do not significantly change as the CPS rotates."
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
