from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import ESC, SMBus, Battery, BMS
from saci_db.vulns.lack_serial_authentification import LackSerialAuthenticationVuln
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

class SMBusBatteryShutdownCPV(CPV):
    
    NAME = "SMBus Battery Shutdown CPV"

    def __init__(self):
        super().__init__(
            required_components=[
                SMBus(),
                BMS(),
                Battery(),
                ESC(),
            ],
            entry_component = SMBus(),      
            exit_component = ESC(),

            vulnerabilities =[LackSerialAuthenticationVuln()],

            initial_conditions ={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "Software state": "Any",
                "Operator Supervision": "Any",
            },
            
            attack_requirements=[
                "BQStudio version 1.3.127",
                "TI EV2400 EVM Interface board"
            ],

            attack_vectors = [BaseAttackVector(name="SMBus shutdown command", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=SMBus()),
                                               required_access_level="Physical",
                                                )],
            attack_impacts = [BaseAttackImpact(category='Loss of control',
                                               description='system does not provide power to subsystem')],
            exploit_steps=[
                "Connect an SMBus cable between the SMBus connector on the EV2400 and J3 on the battery monitor board",
                "Power system on using only battery power",
                "Observe the system is operational, LEDs on the ESC are on",
                "Open BQStudio",
                "If the BQ40Z80 isn't detected automatically BQStudio will prompt the user to select a device",
                "Once connected through BQStudio, observe that the BQ40Z80 status is displayed on the screen",
                "In the commands window click SHUTDOWN twice",
                "The BQ40Z80 will enter shutdown mode disconnecting the power from the system",
                "Observe the ESC board LEDs are disabled."
                ],
                
            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/Greensight1A-esc-CPVs/blob/main/CPV001/HII-GSP1AESC01NR017-CPV001-20240926.docx"]
        )
    
    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass