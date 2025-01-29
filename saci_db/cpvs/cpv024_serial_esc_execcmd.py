from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Motor, ESC, Serial) 
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialESCExeccmdCPV(CPV):

    NAME = "The ESC Execcmd via Serial Interface"

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

            attack_vectors = [BaseAttackVector(name='Serial Get_Info Exec Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='info'),
                                               configuration={'repetitions': '1025'}, #Confirm minimin repetitions necessary for attack to manifest
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
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV007"],
        )


    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
