from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import (Controller, ESC, Motor, Serial)
from saci.modeling.device.motor import Motor
from saci.modeling.state import GlobalState
from saci_db.vulns.serial_spoofing_vuln import SerialSpoofingVuln
from saci_db.vulns.noaps import NoAPSVuln


class RedirectCPV(CPV):
    NAME = "The redirect-the-rover CPV"

    def __init__(self):
        serial_vuln = SerialSpoofingVuln() #Use the LackofAuthentication Class
        no_aps = NoAPSVuln()
        super().__init__(
            required_components=[
                serial_vuln.component,
                Controller(),
                ESC(),
                Motor(),
            ],
            entry_component=serial_vuln.component,
            exit_component=Motor(),

            vulnerabilities=[serial_vuln, no_aps]

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

            attack_vectors = [BaseAttackVector(name='Serial_DSHOT_CMD_SPIN_DIRECTION_1',
                                               src='unauthorized entity',
                                               signal=SerialAttackSignal(src='unauthorized entity', dst=entry_component, data='7'),
                                               dst=Controller(),
                                               required_access_level='physical direct',
                                               ),
                            BaseAttackVector(name='Serial_DSHOT_CMD_SPIN_DIRECTION_2',
                                               src='unauthorized entity',
                                               signal=SerialAttackSignal(src='unauthorized entity', dst=entry_component, data='8'),
                                               dst=Controller(),
                                               configuration={'repetition': '6'},
                                               required_access_level='physical direct',
                                               ),
                            BaseAttackVector(name='Serial_CMD_SAVE_SETTINGS',
                                               src='unauthorized entity',
                                               signal=SerialAttackSignal(src='unauthorized entity', dst=entry_component, data='12'),
                                               dst=Controller(),
                                               configuration={'repetition': '6'},
                                               required_access_level='physical direct',
                                               )],
            attack_requirements = ['computer', 'USB-C cable'],
            attack_impacts = [BaseAttackImpact(category='Manipulation of Control',
                                               description='The CPS moves in opposite direction than expected')],
            
            exploit_steps=[
                "1. Open a terminal emulator and connect to the serial device exposed by the CPS device. You may need root access.",
                "2. In the idle state, you should observe floating point outputs from the compass. If you do not, the retry the previous step.",
                "3. Enter the number '7' six times into the terminal. This corresponds to the DSHOT_CMD_SPIN_DIRECTION_1 setting.",
                "4. Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop",
                "5. Ensure the wheels stop spinning. If the wheel spun in the opposite direction as expected, skip to step 10.",
                "6. Enter the number '8' six times into the terminal window. This corresponds to DSHOT_CMD_SPIN_DIRECTION_2.",
                "7. Use the web interface to command a drive signal. Observe the directions the wheel spin in. Navigate to http://192.168.4.1/Stop",
                "8. Ensure the wheels stop spinning. If the wheel spun in the same direction as expected, the CPS has not been configures to verify the CPV.",
                "9. Enter the number '12' six times to save the DSHOT setings."
                "10. Power down and restart the CPS Device. Use the web interface to command a drive signal."
            ],

            associated_files = [],
            reference_urls = ["https://github.com/senpai-on-fire/NGC1B-rover-CPVs/tree/main/CPV0011"],
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
