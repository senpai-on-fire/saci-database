from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Motor, ESC, Serial) 
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialESCOverflowCPV(CPV):
    
    NAME = "The ESC Buffer Overflow via Serial CPV"

    def __init__(self):
        serial_vuln = LackSerialAuthenticationVuln()
        super().__init__(
            required_components=[
                Serial(),
                ESC(),
                Motor(),
            ],

            entry_component=Serial(),
            exit_component=Motor(),

            vulnerabilities=[serial_vuln],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "BMS": "On",
                "ESC": "On",
                "OperatingMode": "Manual or Mission",
            },

            attack_vectors = [BaseAttackVector(name='Serial ASCII_Characters Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='ASCII Characters'),
                                               configuration={'length': '1025'},
                                               required_access_level='Physical',
                                               ),],

            attack_requirements = ['Computer', 'USB-TTL Serial Adapter with 3.3v logic'],
            attack_impacts = [BaseAttackImpact(category='Denial of Control',
                                               description='Motors stop spinning'),],
            
            exploit_steps=[
                "TA1 Exploit Steps",        
                    "Reverse-engineering the ESC firmware."
                    "Check if the ESC firmware accepts inputs from a serial interface"
                    "Check if the ESC firmware has bounds checking on the serial commands."
                    "Create a model for the Electronic Speec Controller (ESC)"

                "TA2 Exploit Steps",
                    "Create an automata to simulate the buffer overflow attack on the ESC."
                    "Use a fuzzing tool to fuzz the functions and generate a serial command to trigger the buffer overflow."

                "TA3 Exploit Steps",
                    "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.",
                    "Send a the serial command found by TA1/TA2 that is longer than the buffer.",
                    "Observe the impact on the CPS dynamics"
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )


    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
