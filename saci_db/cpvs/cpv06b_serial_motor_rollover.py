from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Controller, ESC, Motor, Serial)
from saci.modeling.device.motor import Motors
from saci.modeling.state import GlobalState
from saci_db.vulns.serial_spoofing_vuln import SerialSpoofingVuln
from saci_db.vulns.noaps import NoAPSVuln


class RollOverCPV(CPV):
    NAME = "The Rollover CPV"

    def __init__(self):
        serial_vuln = SerialSpoofingVuln() #Use the LackofAuthentication Class
        no_aps = NoAPSVuln()
        super().__init__(
            required_components=[
                serial_vuln.component,
                Controller(),
                ESC(),
                Motors(),
            ],
            entry_component=serial_vuln.component,
            exit_component=Motor(),

            vulnerabilities=[serial_vuln, no_aps]

            goals = [],

            intial_conditions={
                "Position": "Any",
                "Heading": "Any", #Change to changing
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving",
                "Operating mode": "Any",
            },

            attack_vectors = [BaseAttackVector(name='Serial_DSHOT_3D_MODE_ON',
                                               src='unauthorized entity',
                                               signal=SerialAttackSignal(src='unauthorized entity', dst=entry_component, data='10'),
                                               dst=Controller(),
                                               configuration={'repetition': '6'},
                                               required_access_level='physical direct',
                                               ),
                              BaseAttackVector(name='Serial_DSHOT_CMD_SAVE_SETTINGS',
                                               src='unauthorized entity',
                                               signal=SerialAttackSignal(src='unauthorized entity', dst=entry_component, data='12'),
                                               dst=Controller(),
                                               configuration={'repetition': '6', 'repetition_window','35'},
                                               required_access_level='physical direct',
                                               ),],
            attack_requirements = ['computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Loss of Safety',
                                               description='The CPS device will move excessively fast')],
            
            exploit_steps=[
                "1. Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "2. In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.",
                "3. With the CPS device in idle state, enter the number 10 six times into the terminal. This corresponds to DSHOT_3D_MODE_ON.",
                "4. With the rover in idle state, enter the number 12 six times. This corresponds to the DSHOT_CMD_SAVE_SETTINGS.",
                "5. Restart the CPS device and control from the web interface.",
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV006"],
        )

    def is_possible_path(self, path: List[CyberComponentBase]):
        required_components = [Serial, Controller, ESC, Motor]
        for required in required_components:
            if not any(map(lambda p: isinstance(p, required), path)):
                return False
        return True

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
