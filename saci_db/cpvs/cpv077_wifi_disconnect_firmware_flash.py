
from saci.modeling import CPV
from saci.modeling.device import Controller, Motor, Wifi
from saci.modeling.communication import ExternalInput
from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.base_attack_impact import BaseAttackImpact
from saci.modeling.state import GlobalState

from saci_db.vulns.firmware_overwrite_vuln import FirmwareOverwriteVuln

class ArduinoGigaFirmwareOverwriteCPV(CPV):

    NAME = "Rover Denial-of-Service via Arduino Giga R1 Firmware Overwrite"

    def __init__(self):
        super().__init__(
            required_components=[
                Controller(),
                Wifi(),
                Motor(),
                #Halima to model ?
                ArduinoGigaR1(),
                #Halima to model ?
                ArduinoUnoR3()
            ],

            entry_component=ArduinoGigaR1(),
            # because the final physical impact is the motors
            # remain inactive due to disrupted command flow (wifi)
            exit_component=Motor(),  

            vulnerabilities=[
                FirmwareOverwriteVuln()
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
                "USB-C cable",
                "Physical access to Arduino Giga R1 USB-C port",
                "Arduino Mbed OS Giga Boards package v4.2.4"
            ],

            attack_vectors=[
                BaseAttackVector(
                    name="Firmware Overwrite via USB-C Port",
                    signal=FirmwareAttackSignal(
                        src=ExternalInput(),
                        dst=ArduinoGigaR1(),
                        modality="firmware_overwrite"
                    ),
                    required_access_level="Physical",
                    configuration={
                        "method": "Arduino IDE USB Upload",
                        "firmware": "Blank Sketch",
                        "interface": "USB-C"
                    }
                )
            ],

            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Overwriting Arduino Giga R1 firmware prevents Wi-Fi network creation, blocks operator access, and stops motor commands."
                )
            ],

            exploit_steps=[
                "TA1/TA2 Exploit Steps",
                "Identify the programmable flash memory on Arduino Giga R1.",
                "Confirm the Arduino Giga R1 is responsible for creating and managing the rover's Wi-Fi network.",

                "TA3 Exploit Steps",
                "Ensure rover is powered off.",
                "Open Arduino IDE on the attacker computer.",
                "Create a new blank sketch with empty setup() and loop() functions.",
                "Connect Arduino Giga R1 to attacker computer via USB-C.",
                "In Arduino IDE, select 'Arduino Giga R1' from board selector.",
                "If the board is not listed, select 'Select other board and port' and choose 'Arduino Giga R1' explicitly.",
                "Select the appropriate USB port in Arduino IDE.",
                "Upload the blank sketch to Arduino Giga R1 via Arduino IDE.",
                "Disconnect Arduino Giga R1 from attacker computer after successful upload.",
                "Power on rover using hex wrench and press the safety button to activate it.",
                "Verify the absence of the rover's Wi-Fi network 'Arduino Wifi' indicating successful exploit.",
                "Attempt to access rover controls via web browser (http://10.0.0.1/) and confirm inability to start missions."
            ],

            associated_files=["arduino_giga_flash_m7.hex"],
            reference_urls=[
                "https://docs.arduino.cc/tutorials/giga-r1-wifi/giga-getting-started/",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV001/HII-NGP1AROV2ARR05-CPV001-20250419.docx"
            ]
        )

    def in_goal_state(self, state: GlobalState):
        # return (not state.component_states[Wifi].is_available and
        #         not state.component_states[Motor].is_operational)
        #TODO
        pass
