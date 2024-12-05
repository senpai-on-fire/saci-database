from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import ESC, Serial
from saci_db.vulns.lack_serial_authentification import LackSerialAuthenticationVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

class ESCResetCPV(CPV):
    
    NAME = "Serial ESC Reset CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                ESC(),
            ],
            entry_component = Serial(),
            exit_component = ESC(),

            vulnerabilities =[LackSerialAuthenticationVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any", 
                "Speed": "Any", 
                "Environment": "Any", 
                "Software state": "On",
                "Operator Supervision": "Any"
            },
            
            attack_requirements=[
                "physical access",
                "Microprocessor Programmer",
                "1-Wire Serial Interface Adapter",
                "Terminal Emulator Software"
            ],

            attack_vectors = [BaseAttackVector(name="Serial interface command injection", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial()),
                                               required_access_level="Physical",
                                                )],

            attack_impacts = [BaseAttackImpact(category='Loss of availability',
                                               description='ESC will repeatedly reset every 3s')],
            exploit_steps=[
                "Send a throttle command of zero to initialize the motor/firmware state.",
                "Send a throttle command to engage the motor and observe that the motor begins to spin.",
                "Send a throttle command of zero to stop the motor.", 
                "Reset power to ESC. In theory this should not be necessary, but in practice values could not be set reliably if a non-zero throttle had been commanded within the same power cycle.",
                "Send the data following data to set the prot_volt configuration value:",
                "Send the data following data to set the prot_cells configuration value:",
                "Save the configuration changes",
                "Repeat steps 1 & 2 to engage the motor.",
                "Observe that the motor either begins to spin and stops within three seconds or will not start at all"
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV004/HII-GSP1AESC01NR017-CPV004-20241003.docx"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass