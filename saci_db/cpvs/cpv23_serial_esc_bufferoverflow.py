from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Motor, ESC, Serial) 
from saci.modeling.state import GlobalState
from saci_db.vulns.lack_serial_authentification import LackSerialAuthenticationVuln
from saci.modeling.device.component import CyberComponentBase

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class OverflowCPV(CPV):
    NAME = "The Buffer Overflow CPV"

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
                "Operating mode": "Any",
            },

            attack_vectors = [BaseAttackVector(name='Serial_ASCII_Characters',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='ASCII Characters'),
                                               configuration={'length': '1025'},
                                               required_access_level='Physical',
                                               ),],

            attack_requirements = ['Computer', 'USB-TTL Serial Adapter with 3.3v logic'],
            attack_impacts = [BaseAttackImpact(category='Denial of Control',
                                               description='Motors stop spinning'),],
            
            exploit_steps=[
                "Connect the USB-TTL Serial Adapter to the RC_1 test point on the ESC.",
                "Send a Serial Command that is longer than the buffer.",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )


    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
