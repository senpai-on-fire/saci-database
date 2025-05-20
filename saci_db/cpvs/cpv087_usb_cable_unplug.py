from saci.modeling import CPV

from saci.modeling.attack.base_attack_signal import BaseAttackSignal
from saci.modeling.attack.base_attact_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import Serial, Controller, ESC, PWMChannel, Motor
from saci.modeling.state import GlobalState

from saci_db.vulns import ExposedSerialConnectionVuln, LackFailsafeDisconnectionVuln

class UsbCableUnplugCPV(CPV):

    NAME = "The USB Cable Unplug Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                Controller(),
                PWMChannel(),
                ESC(),
                Motor()
            ],
            entry_component = Serial(),
            exit_component = Motor(),

            vulnerabilities = [ExposedSerialConnectionVuln(), LackFailsafeDisconnectionVuln()], 

            initial_conditions = {
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "On or Moving",
                "Operating mode": "Mission"
            },

            attack_requirements=[
                "Computer",
                "USB-C Cable"
            ],

            attack_vectors = [BaseAttackVector(name="USB Disconnection",
                                               signal=BaseAttackSignal(src=Serial(), dst=Controller(), modality="USB Connection"),
                                               required_access_level="Physical",
                                               )],
            attack_impacts = [BaseAttackImpact(category='Denial of Service',
                                               description='The CPS is unable to respond to commands while unplugged.')],

            exploit_steps = [
                "TA1 Exploit Steps",
                    "Reverse-engineer the CPS firmware to determine if it implements safeguards in the case of disconnection with physical communication interfaces.",
                    "Identify if the firmware authenticates physical connections.",
                    "Analyze the CPS control logic to asses how a disruption in a physical communication connection would affect the operation of the CPS.",
                    "Report to TA3 any possible exploits with regards to communication disruption."

                
                "TA2 Exploit Steps",
                    "There are no steps for simulation to be done by TA2 in this exploit.",

                "TA3 Exploit Steps",
                    "Connect to the CPS through a wireless interface and a physical serial connection (like USB-C).",
                    "Utilizing the physical serial connection, access the serial communications through a terminal emulator.",
                    "Issue a command through the wireless interface to start the mission.",
                    "Disconnect the physical serial connection and then attempt to issue a command through the wireless interface.",
                    "Observe if the disconnection of the physical interface allows the mission to continue unsafely and disregards commands from the wireless interface.c"
            ],

            associated_files=[],
            reference_urls=["https://github.com/senpai-on-fire/ngc2_taskboard/tree/main/CPVs/HII-NGP1AROV2ARR05-CPV018"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass