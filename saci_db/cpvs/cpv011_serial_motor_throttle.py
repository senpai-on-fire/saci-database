from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Controller, ESC, PWMChannel, Serial)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

class SerialThrottleCPV(CPV):

    NAME = "The Throttle the Rover via Serial Interface"

    def __init__(self):
        serial_vuln = LackSerialAuthenticationVuln() #Use the LackofAuthentication Class
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                Controller(),
                PWMChannel(), 
                ESC(),
                Motor(),
            ],
            entry_component=Serial(),
            exit_component=Motor(),

            vulnerabilities=[serial_vuln,],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "OperatingMode": "Manual or Mission",
            },

            attack_vectors = [BaseAttackVector(name='Serial DSHOT Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='any'), #data excludes values 55, 66, 77
                                               required_access_level='Physical',
                                               )],
            attack_requirements = ['Computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Manipulation of Control',
                                               description='The serial commands cause CPS device to start moving/driving')],
            
            exploit_steps=[
                "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "When the CPS is Idle, enter any number between 48-2047 (except 55, 66, & 77) into the terminal",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
