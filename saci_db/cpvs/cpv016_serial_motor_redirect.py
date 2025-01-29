from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Controller, ESC, Motor, Serial, PWMChannel, ESC)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState

from saci_db.vulns.noaps import NoAPSVuln
from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal 
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput

class SerialRedirectCPV(CPV):

    NAME = "The Redirect the CPS Motor via Serial Interface"

    def __init__(self):

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

            vulnerabilities=[LackSerialAuthenticationVuln()],

            goals = [],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Any",
            },

            attack_vectors = [BaseAttackVector(name='Serial DSHOT_CMD_SPIN_DIRECTION_1 Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='7'),
                                               configuration={'repetition': '6'},
                                               required_access_level='Physical',
                                               ),
                            BaseAttackVector(name='Serial DSHOT_CMD_SPIN_DIRECTION_2 Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='8'),
                                               configuration={'repetition': '6'},
                                               required_access_level='Physical',
                                               ),
                            BaseAttackVector(name='Serial CMD_SAVE_SETTINGS Command Injection',
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial(), data='12'),
                                               configuration={'repetition': '6'},
                                               required_access_level='Physical',
                                               )],
            attack_requirements = ['Computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Manipulation of Control',
                                               description='The CPS moves in opposite direction than expected')],
            
            exploit_steps=[
                "Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.",
                "Enter the number '7' six times into the terminal. This corresponds to the DSHOT_CMD_SPIN_DIRECTION_1 setting.",
                "Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop",
                "Ensure the wheels stop spinning. If the wheel spun in the opposite direction as expected, skip to step 10.",
                "Enter the number '8' six times into the terminal window. This corresponds to DSHOT_CMD_SPIN_DIRECTION_2.",
                "Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop",
                "Ensure the wheels stop spinning. If the wheel spun in the same direction as expected, the CPS has not been configures to verify the CPV.",
                "Enter the number '12' six times to save the DSHOT setings."
                "Power down and restart the CPS Device. Use the web interface to command a drive signal."
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011"],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
