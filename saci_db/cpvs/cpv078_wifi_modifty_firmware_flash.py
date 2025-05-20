
from saci.modeling import CPV
from saci.modeling.device import Controller, Motor, Wifi
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.firmware_overwrite_vuln import FirmwareOverwriteVuln

class ArduinoUnoFirmwareOverwriteCPV(CPV):

    NAME = "Rover Denial-of-Service via Arduino Uno R3 Firmware Overwrite"

    def __init__(self):
        super().__init__(
            required_components=[
                ArduinoUnoR3(),
                ArduinoGigaR1(),
                Controller(),
                Wifi(),
                Motor(),
            ],

            entry_component=ArduinoUnoR3(),
            # Motor remains inactive due to firmware overwrite preventing command relay.
            exit_component=Motor(),  

            vulnerabilities=[
                FirmwareOverwriteVuln(component=ArduinoUnoR3())
            ],

            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "Off",
                "CPSController": "Powered Off",
                "OperatingMode": "N/A"
            },

            attack_requirements=[
                "Computer with Arduino IDE v2.3.6",
                "USB-B cable",
                "Physical access to Arduino Uno R3 USB port",
                "Arduino AVR Boards package v1.8.6"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via USB-B Port",
                    signal=FirmwareAttackSignal(
                        src=ExternalInput(),
                        dst=ArduinoUnoR3(),
                        modality="firmware_overwrite"
                    ),
                    required_access_level="Physical",
                    configuration={
                        "method": "Arduino IDE USB Upload",
                        "firmware": "Blank Sketch",
                        "interface": "USB-B"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Overwriting Arduino Uno R3 firmware disrupts CAN communication with Arduino Giga R1, making web interface unreachable and preventing rover operation."
                )
            ],

            exploit_steps=[
                "TA1/TA2 Exploit Steps",
                "Identify Arduino Uno R3 programmable flash memory and confirm communication dependencies with Arduino Giga R1.",
                "Verify the impact of firmware overwrite on rover control functionalities.",

                "TA3 Exploit Steps",
                "Ensure rover is powered off.",
                "Open Arduino IDE on the attacker computer.",
                "Create a new blank sketch with empty setup() and loop() functions.",
                "Connect Arduino Uno R3 to attacker computer via USB-B.",
                "In Arduino IDE, select 'Arduino UNO' from board selector.",
                "If the board is not listed, select 'Select other board and port' and choose 'Arduino UNO' explicitly.",
                "Select the appropriate USB port in Arduino IDE.",
                "Upload the blank sketch to Arduino Uno R3 via Arduino IDE.",
                "Disconnect Arduino Uno R3 from attacker computer after successful upload.",
                "Power on rover using hex wrench and press the safety button to activate it.",
                "Connect to rover Wi-Fi ('Arduino Wifi') and attempt to access rover controls via web browser (http://10.0.0.1/).",
                "Verify the web page does not load and confirm inability to start missions."
            ],

            associated_files=["arduino_r3_flash.ihex.hex", "upload.sh"],
            reference_urls=[
                "https://docs.arduino.cc/software/ide-v2",
                "https://docs.arduino.cc/hardware/uno-rev3",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV002/HII-NGP1AROV2ARR05-CPV002-20250419.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # return (not state.component_states[Wifi].interface_accessible and
        #         not state.component_states[Motor].is_operational)
        #TODO
        pass
