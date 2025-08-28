
from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Motor,
    Serial,
)
from saci.modeling.state import GlobalState

from saci_db.vulns.lack_serial_auth_vuln import LackSerialAuthenticationVuln

from saci.modeling.attack.serial_attack_signal import SerialAttackSignal
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.communication import ExternalInput


class SerialToneCPV(CPV):
    NAME = "The Audible Tone in CPS Motors via Serial Interface"

    def __init__(self):
        super().__init__(
            
            required_components=[
                Serial(), # This is the entry component (Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            
            entry_component=Serial(),
            exit_component=Motor(),
            
            vulnerabilities=[LackSerialAuthenticationVuln()],
            
            goals=[],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "Any",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Moving or Idle",
                "OperatingMode": "Manual or Mission",
            },
            
            attack_vectors=[
                BaseAttackVector(
                    name="Serial Command Injection",
                    signal=SerialAttackSignal(
                        src=ExternalInput(), dst=Serial(), data="ASCII numbers 1-5"
                    ),
                    required_access_level="Physical",
                ),
                BaseAttackVector(
                    name="Serial Command Injection",
                    signal=SerialAttackSignal(
                        src=ExternalInput(), dst=Serial(), data="PgUp key"
                    ),
                    required_access_level="Physical",
                ),
            ],
            
            attack_requirements=["Computer", "USB-C cable"],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Loss of Productivity and Revenue",
                    description="The CPS ESC/Motor generates a repeating tone"
                    "that varies in pitch based upon the character sent",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Implement a Model to simulate the audible tones manipulation in Motors",
                    "The model must include:",
                    "    - Control logic algorithm.",
                    "    - Any required physical parameters to simulate CPS dynamics.",
                    "    - Electronic speed controller logic and output.",
                    "    - CPS actuators (e.g., motors) controlled by the ESC.",
                "TA2 Exploit Steps",
                    "Simulate the fault injection attack to trigger audible tones in motors",
                    "Find all the commands that trigger the attack based on TA1 models findings",
                "TA3 Exploit Steps",
                    "Power CPS on",
                    "Connect a USB cord to the USB-C port on the Arduino Uno R4",
                    "Open a terminal emulator and connect to the serial device exposed by the Arduino Uno R4",
                    "On Linux this can be accomplished with the command:",
                    "> tio /dev/ttyACM0"
                    "The exact name of the serial device may vary based on system settings and other attached serial devices. ",
                    "The command “dmesg | tail” may help identify the named device. You may need to have root permissions, or be a member of the “dialout” group to open the device.",
                    " Other programs like minicom or screen can be used to connect to a serial device, but the CPV has not been tested with those programs and we cannot verify what command-line options may need to be provided.",
                    "The serial device communicates at a baud rate of 115200 (which is the default for tio).",
                    "On Windows you can use putty to attach to a serial device. ",
                    "In the idle state the CPS should repeatedly print readings from the digital compass in the form of one floating point number per line.",
                    " If you do not see this output on your terminal emulator then communication to the serial device is not set up correctly and the CPV will likely not be able to be triggered as described.",
                    "Press any number key within the range 1-5 or the PgUp key on the computer keyboard.",
                    "Observe that the ESC/Motor is generating a repeated tone.",
            ],
            
            associated_files=[],
            reference_urls=[
                "https://github.com/senpai-on-fire/NGC1B-CPS-CPVs/tree/main/CPV004"
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # TODO?
        pass
