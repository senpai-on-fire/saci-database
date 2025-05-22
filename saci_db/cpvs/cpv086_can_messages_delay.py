from typing import List, Type
from saci.modeling import CPV
from saci.modeling.device import Controller, Wifi, Controller, Motor, WebServer, PWMChannel, ESC, CANBus, CANTransceiver, CANShield, Telemetry


from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector

from saci.modeling.state import GlobalState
 
from saci_db.vulns.can_pwm_scheduling_vuln import CANPWMSchedulingVuln

class CANMessagesDelayCPV(CPV):

    NAME = "This is just a hypothesis, not really a full CPV : PWM generation process starvation using highly frequent CAN bus messages."

    def __init__(self):

        super().__init__(
            required_components=[
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),                     
                Controller(),     
                PWMChannel(),     
                ESC(),            
                Motor(),          
            ],

            entry_component=Controller(),
            exit_component=Motor(),

            vulnerabilities=[CANPWMSchedulingVuln()],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "Any",
                "CPSController": "Idle",
                "Operating mode": "Any"
            },

            attack_requirements=["Laptop connected over Wifi",
                                 "Rover is powered on"],

            attack_vectors=[
                BaseAttackVector(
                    name="Some form of input to increase the CAN message frequency",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Controller()),
                    required_access_level="Unknown",
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category='Denial of Service',
                    description='The drone can potentially crash.'
                )
            ],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "None",

                "TA2 Exploit Steps",
                    "None",

                "TA3 Exploit Steps",
                    "There are currently no tested and proven steps to exploitation. A hypothesis is described below",
                    "1.	Increase CAN message frequency coming from the Giga",
                    "   The Giga sends a CAN message every 100ms while the wheels on the rover are turning. A future exploit could increase the frequency of these messages",
                    "To simulate the effect of this denial of service, you can disconnect the signal pin from the ESC (pin 10 on the Uno) while the rover is in operation.",
            ],

            associated_files=[""],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV016/HII-NGP1AROV2ARR05-CPV016-20250514.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        #TODO
        #return state.component_states[WebServer].availability == False and state.component_states[Controller].accessibility == "AttackerOnly"
        pass
      
    