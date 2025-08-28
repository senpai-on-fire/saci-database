from saci.modeling import CPV
from saci.modeling.device import (
    Controller,
    Motor,
    Serial,
)
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.attack.packet_attack_signal import PacketAttackSignal
from saci.modeling.state import GlobalState

from saci_db.vulns.firmware_overwrite_vuln import FirmwareOverwriteVuln


class ArduinoUnoFirmwareOverwriteCPV(CPV):
    NAME = "Rover Denial-of-Service via Arduino Uno R3 Firmware Overwrite"

    def __init__(self):
        super().__init__(
            required_components=[
                Serial(),  # This is the entry component (Required)
                Controller(),  # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(),  # This is the exit component + Changed to Motor() for generalization (Required)
            ],
            entry_component=Serial(),
            exit_component=Motor(),  # Motor inactivity due to CAN communication disruption.
            vulnerabilities=[FirmwareOverwriteVuln()],
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "Off",
                "CPSController": "Powered Off",
                "OperatingMode": "N/A",
            },
            attack_requirements=[
                "Computer with Arduino IDE v2.3.6",
                "USB-B cable",
                "Physical access to Arduino Uno R3 USB-B port",
                "Arduino AVR Boards package v1.8.6",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via USB-C Port",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Serial(), modality="firmware_overwrite"),
                    required_access_level="Physical",
                    configuration={
                        "method": "Arduino IDE USB Upload",
                        "firmware": "Blank Sketch",
                        "interface": "USB-B",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Overwriting Arduino Uno R3 firmware disrupts CAN communication with Arduino Giga R1, making the web interface unreachable and preventing rover operation.",
                )
            ],
            exploit_steps=[
                "TA1/TA2 Exploit Steps",
                "Identify Arduino Uno R3 manages critical CAN communication required for rover mission control.",
                "Confirm the programmable flash memory vulnerability on Arduino Uno R3.",
                "TA3 Exploit Steps",
                "Open “Arduino IDE”.",
                "Select “File” -> ”New Sketch”.",
                "A new sketch window should open with empty setup() and loop() functions defined.",
                "Connect the Arduino Uno R3 to the computer with the USB-B cable.",
                "Using the board selector at the top of the window, select “Arduino UNO”.",
                "If “Arduino UNO” is not present, select “Select other board and port”.",
                "A dialog titled “Select Other Board and Port” should appear.",
                "Type in “Arduino UNO” into the “Boards” text box, and select “Arduino UNO” in the list box below.",
                "Select the appropriate port in the “Ports” dialog box.",
                "Press the “OK” button.",
                "Save this sketch with the name “blank” or something appropriate.",
                "Select “Sketch” -> “Upload” to compile and upload the sketch to the board.",
                "Once the upload has finished, unplug the Arduino Uno R3 from the computer.",
                "Repeat Steps #1-3 in the first section to power and activate the rover.",
                "Open a web browser on the computer and navigate to http://10.0.0.1/.",
                "Observe that the web page will not load and a mission cannot be started.",
                "Using a hex wrench, rotate the power block clockwise until the LEDs turn off to power off the rover.",
            ],
            associated_files=["arduino_r3_flash.ihex.hex", "upload.sh"],
            reference_urls=[
                "https://docs.arduino.cc/software/ide-v2",
                "https://docs.arduino.cc/hardware/uno-rev3",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV002/HII-NGP1AROV2ARR05-CPV002-20250419.docx",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # return (not state.component_states[Wifi].interface_accessible and
        #         not state.component_states[Motor].is_operational)
        # TODO
        pass
