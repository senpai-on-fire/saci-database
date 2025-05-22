from saci.modeling import CPV

from saci.modeling.attack.base_attack_signal import BaseAttackSignal
from saci.modeling.attack.base_attact_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.device import (
    Serial,
    Controller,
    ESC,
    PWMChannel,
    Motor,
    CANBus,
    CANTransceiver,
    CANShield,
)
from saci.modeling.state import GlobalState

from saci_db.vulns import ExposedSerialConnectionVuln, LackFailsafeDisconnectionVuln


class UsbCableUnplugCPV(CPV):
    NAME = "The USB Cable Unplug Attack"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),
                Controller(),
                CANTransceiver(),
                CANBus(),
                CANShield(),
                Controller(),
                PWMChannel(),
                ESC(),
                Motor(),
            ],
            entry_component=Serial(),
            exit_component=Motor(),
            vulnerabilities=[
                ExposedSerialConnectionVuln(),
                LackFailsafeDisconnectionVuln(),
            ],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "On or Moving",
                "Operating mode": "Mission",
            },
            attack_requirements=["Computer", "USB-C Cable"],
            attack_vectors=[
                BaseAttackVector(
                    name="USB Disconnection",
                    signal=BaseAttackSignal(
                        src=Serial(), dst=Controller(), modality="USB Connection"
                    ),
                    required_access_level="Physical",
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="The CPS is unable to respond to commands while unplugged.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "Reverse-engineer the CPS firmware to determine if it implements safeguards in the case of disconnection with physical communication interfaces.",
                "Identify if the firmware authenticates physical connections.",
                "Analyze the CPS control logic to asses how a disruption in a physical communication connection would affect the operation of the CPS.",
                "Report to TA3 any possible exploits with regards to communication disruption."
                "TA2 Exploit Steps",
                "There are no steps for simulation to be done by TA2 in this exploit.",
                "TA3 Exploit Steps",
                "Power on the rover using a hex wrench to rotate the power block counter-clockwise.",
                "Wait for the rover LEDs to indicate readiness, then press the safety button on the power block.",
                "Connect both operator and attacker computers to the rover's Wi-Fi network ('Arduino Wifi' using password 'TSWIZZLE1989').",
                "Use a USB-C cable to connect the Arduino Giga R1 to a computer and open the serial monitor.",
                "Open the rover web interface on the operator computer at http://10.0.0.1/.",
                "Start a mission on the rover using one of the available options and observe that the rover begins to drive.",
                "Navigate to http://10.0.0.1/Stop to stop the rover.",
                "Unplug the USB-C cable, attempt to start another misison on the rover, and notice that the rover does not start driving.",
                "Plug the USB-C cable back into the rover and notice that the rover starts driving immediately.",
                "Navigate to http://10.0.0.1/Stop to stop the rover, start another mission on the rover, and observe that the rover does drive.",
                "While the rover is moving, disconnect the USB-C cable and then navigate to http://10.0.0.1/Stop to stop the rover.",
                "Observe that the rover does not stop and also fails the mission objective.",
                "Plug the USB-C cable back into the rover and stop the rover.",
            ],
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/ngc2_taskboard/tree/main/CPVs/HII-NGP1AROV2ARR05-CPV018"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO
        pass
