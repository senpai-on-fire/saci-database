from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Controller, PWMChannel, ESC, Serial)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialRollOverCPV(CPV):

    NAME = "The Roll-the-Rover-Over via Serial Interface"

    def __init__(self):

        serial_vuln = LackSerialAuthenticationVuln()

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

            vulnerabilities=[serial_vuln],

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

            attack_vectors = [BaseAttackVector(name='Serial DSHOT_3D_MODE_ON Commands Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='10'),
                                               configuration={'repetition': '6'},
                                               required_access_level='Physical',
                                               ),
                              BaseAttackVector(name='Serial DSHOT_CMD_SAVE_SETTINGS Commands Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='12'),
                                               configuration={'repetition': '6', 'repetition_window':'35'},
                                               required_access_level='Physical',
                                               ),],

            attack_requirements = ['Computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Loss of Safety',
                                               description='The CPS device will move excessively fast'),
                              BaseAttackImpact(category='Damage to Property',
                                             description='The CPS device will rollover')],
            
            exploit_steps=[
                "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.",
                "With the CPS device in idle state, enter the number 10 six times into the terminal. This corresponds to DSHOT_3D_MODE_ON.",
                "With the rover in idle state, enter the number 12 six times. This corresponds to the DSHOT_CMD_SAVE_SETTINGS.",
                "Restart the CPS device and control from the web interface.",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )


    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
