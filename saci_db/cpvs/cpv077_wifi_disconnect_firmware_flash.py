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


class ArduinoGigaFirmwareOverwriteCPV(CPV):
    NAME = "Rover Denial-of-Service via Arduino Giga R1 Firmware Overwrite"

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
            exit_component=Motor(),  # Exit component is Motor because the final impact is motor inactivity due to firmware overwrite.
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
                "USB-C cable",
                "Physical access to Arduino Giga R1 USB-C port",
                "Arduino Mbed OS Giga Boards package v4.2.4",
            ],
            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via USB-C Port",
                    signal=PacketAttackSignal(src=ExternalInput(), dst=Serial(), modality="firmware_overwrite"),
                    required_access_level="Physical",
                    configuration={
                        "method": "Arduino IDE USB Upload",
                        "firmware": "Blank Sketch",
                        "interface": "USB-C",
                    },
                )
            ],
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Firmware overwrite on Arduino Giga R1 prevents Wi-Fi network creation, blocking operator control and motor operation.",
                )
            ],
            exploit_steps=[
                "TA1 Exploit Steps",
                "No formal modeling was done for this CPV",
                "TA2 Exploit Steps",
                "No formal modeling was done for this CPV",
                "TA3 Exploit Steps",
                "Open “Arduino IDE”.",
                "Select “File” -> ”New Sketch”.",
                "A new sketch window should open with empty setup() and loop() functions defined.",
                "Connect the Arduino Giga R1 to the computer with the USB-C cable.",
                "Using the board selector at the top of the window, select “Arduino Giga R1”.",
                "If “Arduino Giga R1” is not present, select “Select other board and port”.",
                "A dialog titled “Select Other Board and Port” should appear.",
                "Type in “Arduino Giga R1” into the “Boards” text box, and select “Arduino Giga R1” in the list box below.",
                "Select the appropriate port in the “Ports” dialog box.",
                "Press the “OK” button.",
                "Save this sketch with the name “blank” or something appropriate.",
                "Select “Sketch” -> “Upload” to compile and upload the sketch to the board.",
                "Once the upload has finished, unplug the Arduino Giga R1 from the computer.",
                "Repeat Steps #1-2 in the first section.",
                "The “Arduino Wi-Fi” network will not be present and you will be unable to start a mission.",
                "Using a hex wrench, rotate the power block clockwise until the LEDs turn off to power off the rover.",
            ],
            associated_files=["original_giga_r1_firmware.bin"],
            reference_urls=[
                "https://docs.arduino.cc/tutorials/giga-r1-wifi/giga-getting-started/",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV001/HII-NGP1AROV2ARR05-CPV001-20250419.docx",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # Check if the exploit succeeded: Wi-Fi network should be unavailable, and the motor should not operate.
        # return (not state.component_states[Wifi].is_available and
        #         not state.component_states[Motor].is_operational)
        # TODO
        pass
