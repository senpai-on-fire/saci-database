from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (CyberComponentBase, Controller, ESC, Serial)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState
from saci_db.vulns.serial_spoofing_vuln import SerialSpoofingVuln
from saci_db.vulns.noaps import NoAPSVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class ThrottleCPV(CPV):
    NAME = "The throttle-the-rover CPV"

    def __init__(self):
        serial_vuln = SerialSpoofingVuln() #Use the LackofAuthentication Class
        no_aps = NoAPSVuln()
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                ESC(),
                Motor(),
            ],
            entry_component=Serial(),
            exit_component=Motor(),

            vulnerabilities=[serial_vuln, no_aps],

            goals = [],

            intial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Any",
            },

            attack_vectors = [BaseAttackVector(name='Serial_DSHOT_Command',
                                               src='Unauthorized entity',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='any'),#data excludes values 55, 66, 77
                                               dst=Controller(),
                                               required_access_level='physical',
                                               )],
            attack_requirements = ['computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Manipulation of Control',
                                               description='The serial commands cause CPS device to start moving/driving')],
            
            exploit_steps=[
                "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "When the CPS is Idle, enter any number between 48-2047 (except 55, 66, & 77) into the terminal",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011"],
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        for required in self.required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
