from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import Motor, ESC, Debug

from saci.modeling.communication import ExternalInput

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class SerialESCBootloaderCPV(CPV):
    
    NAME = "The ESC Bootloader via Serial Interface"

    def __init__(self):
        super().__init__(
            required_components=[
                Debug(),
                ESC(),
                Motor(),
            ],
            entry_component = Debug(),
            exit_component = Motor(),

            vulnerabilities =[LackSerialAuthenticationVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state": "On",
                "Operator Supervision": "Any",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_requirements=[
                "physical access",
                "Debugging/programming hardware",
                "Software tools for accessing and programming STM32 microprocessors.",
                "Knowledge of STM32 boot-loader mode",
                "knowledge of programming protocols."
            ],

            attack_vectors = [BaseAttackVector(name="Debug Commands Injection", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Debug()),
                                               required_access_level="Physical",
                                                )],
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='ESC will not start motor')],
            exploit_steps=[
                "Connect to the ESC via a USB-TTL serial adapter using a terminal emulator with a baud rate of 38400.",
                "Arm the ESC and start the motor.",
                "Use the microprocessor programmer to connect to the STM32.",
                "Follow the procedure to write the HII-GSP1AESC01NR017-CPV003_FF.hex file to the STM32.",
                "Use the microprocessor programmer to reset the STM32.",
                "Reconnect to the USB-TTL serial adapter using the terminal emulator.",
                "The terminal emulator will likely not connect and the motor does not begin to spin."
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV003/HII-GSP1AESC01NR017-CPV003-20241002.docx"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass