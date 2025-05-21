<<<<<<< HEAD
from typing import List, Type

from saci.modeling import CPV
from saci.modeling.device import PassThrough, Controller, GPS, Motor, PWMChannel, WebServer, WebClient, ESC
from saci.modeling.device.motor import Steering
from saci.modeling.device.interface import Serial

from saci.modeling.communication import ExternalInput

from saci.modeling.attack.packet_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

# -This needs the passthrough element to run a Linux OS
# -It also needs the process to be a foreground process
# -I did not include those in attack_requirements or required_components

# -The passthrough element is one of the ARM cores in the ZynQ SoC, should I model it as passthrough element now
# or make it a general processor, or an ARM processor or specify it is a processor on a FPGA SoC or identify the exact
# model (Zynq 7020 SoC ARM Core) ?

class GPSPassthroughStopCPV(CPV):
    
    NAME = "Terminate GPS signal passthrough process "

    def __init__(self):
        super().__init__(
            required_components=[
                GPS(),
                Serial(),
                PassThrough(),
                Controller(),
                #PWMChannel(),
                Steering(),
            ],
            entry_component= Serial(),
            exit_component= Steering(),

            vulnerabilities=[LackSerialAuthenticationVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "Any",
                "CPSController": "Idle",
                #"GPS Lock" : "Acquired",
                "Operating mode": "Mission"
            },
            attack_requirements=[
                "Attacker computer",
                "physical access",
                "USB to Serial Interface Adapter",
                "Terminal Emulator Software"
            ],
            attack_vectors = [BaseAttackVector(name="Terminate Passthrough Process", 
                                               signal=SerialAttackSignal(src=ExternalInput(), dst=Serial()),
                                               required_access_level="Physical",
                                               #configuration={"duration": "permanent"},
                                                )],  
            attack_impacts = [BaseAttackImpact(category='Loss of control.',
                                               description='The CPS starts driving in a stright line without turning')],

            exploit_steps=[
                "TA1 Exploit Steps",
                    "1-Wait for TA3 reporting whether verification was successful or not."
                    "2-If successful : Analyze the passthrough element OS boot process and verify that the passthrough binary launches in the foreground before authentication",
                    "3-Report findings to TA3",

                "TA2 Exploit Steps",
                    "1-Simulate the effect of constant GPS signal on the rover mission to verify the impact",
                    "2-Report the impact to TA3",

                "TA3 Exploit Steps",
                    "A- Reverse Engineering"
                    "   1-Use optical imaging tools to catalog all of the components on the CPS.",
                    "   2-Verify the existance of a passthrough component that is connected to the GPS receiver and the microcontroller",
                    "   3-Localize the serial port used to connect to the passthrough component and identify its physical layer protocol",
                    "   4-Identify the OS running on the passthrough element and verify it is a Linux OS",
                    "   5-If steps 2,3 and 4 were verified successfully, report findings to TA1 and TA2.",
                    "B- Replicate the attack:",
                    "   Components:",
                    "       1- Serial to USB adapter (Exact Serial adapter based on step A-3)",
                    "       2- Attacker Laptop with terminal emulator software",
                    "       3- USB cable",
                    "   Steps:",
                    "       1.	Connect a USB-C cable to the microcontroller but do not plug the other end into a computer. This will prematurely power the microcontroller.",
                    "       2.	Plug the serial connector of the serial adapter into the connector labeled UART1 on the passthrough board. Plug the USB connector of the serial adapter into the computer. As serial doesn’t provide power this will not power the passthrough board.",
                    "       3.	Position the USB connector of the cable connected to the microcontroller near the computer so it can be plugged in quickly.",
                    "       4.	Open up one terminal emulator for the serial device exposed by the microcontroller.",
                    "       5.	Open up a second terminal emulator for the serial device exposed by the serial adapter.",
                    "       6.	Using a hex wrench, rotate the power block counter-clockwise to power on the rover.",
                    "       7.	Quickly plug in the USB cable connected to the microcontroller into the computer.",
                    "       8.	On the terminal emulator connected to the microcontroller you should see messages about creating the Wi-Fi interface and sensor initialization. Depending on how recently the GPS receiver has been powered on, it may immediately find a GPS lock. You will see a messages printed to the console indicating the coordinates. If a GPS lock is not established you will see messages with \"********\" printed. Wait until messages similar to Figure #2 appear.",
                    "       9.	Simultaneously, on the terminal emulator you will see the embedded Linux system boot sequence. This should continue until you see a bootup message and then output will stop. If you do not see this message stop the testing procedure as the rest of the test is unlikely to behave as expected.",
                    "       10.	Once the GPS lock messages are seen from Step #8, in the terminal emulator connected to the serial adapter enter “Ctrl-C”. This will cause the embedded Linux system to continue progressing through the boot process. You should see a login prompt.",
                    "       11.	Disconnect the USB cable from the microcontroller.",
                    "       12.	Disconnect the serial adapter from the passthrough board.",
                    "       13.	There should not be any cables connected to the rover at this point. Initiate a mission and verify the impact.",
                    "       14.	Turn the rover off then back on again. Note that subsequent powering of the rover will launch the “passthrough” program as expected and no further recovery procedures are needed.",
            ],
            associated_files=["https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV007/hii_cpv007_terminate_passthrough.mp4"],
            reference_urls=["https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV007/HII-NGP1AROV2ARR05-CPV007-20250425.docx"]
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
=======

>>>>>>> fe6e7f5bc2946b58e9cb4fdb2fc003ad2dc0a6ac
