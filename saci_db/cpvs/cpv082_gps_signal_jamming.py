
from saci.modeling.device import (
    Controller,
    GPSReceiver,
    Motor,
)
from saci.modeling import CPV

from saci_db.vulns.gps_spoofing_vuln import GPSSpoofingVuln
from saci_db.vulns.lack_gps_filtering_vuln import LackGPSFilteringVuln
from saci_db.vulns.controller_integerity_vuln import ControllerIntegrityVuln
from saci_db.vulns.gps_jamming_vuln import GPSJammingVuln


from saci.modeling.communication import ExternalInput

from saci.modeling.attack.base_attack_vector import BaseAttackVector
from saci.modeling.attack.gps_attack_signal import GPSAttackSignal
from saci.modeling.attack.base_attack_impact import BaseAttackImpact

from saci.modeling.state import GlobalState


class GPSJammingNoDriveCPV(CPV):
    NAME = "GPS Jamming Preventing Rover Drive Operation"

    def __init__(self):
        super().__init__(
            required_components=[
                GPSReceiver(), # This is the entry component (Required)
                # Serial(), # Removed considering that the GPSReceiver is inherently connected to the Controller via Serial (Not Required)
                Controller(), # This is the controller hosting the firmware (Required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANTransceiver(), # Removed for generalization since it's not required and too specific (Not required)
                # CANBus(), # Removed for generalization since it's not required and too specific (Not required)
                # CANShield(), # Removed for generalization since it's not required and too specific (Not required)
                # PWMChannel(), # Removed since the PWMChannel is just a passthrough for the CPV (Not Required)
                # ESC(), # Removed since the ESC is just a passthrough for the CPV (Not Required)
                Motor(), # This is the exit component + Changed to Motor() for generalization (Required)
            ],

            entry_component=GPSReceiver(),
            exit_component=Motor(),
            
            vulnerabilities=[GPSSpoofingVuln(), LackGPSFilteringVuln(), ControllerIntegrityVuln(), GPSJammingVuln()],
            
            initial_conditions={
                "Position": "Any",
                "Heading": "Any",
                "Speed": "0",
                "Environment": "Any",
                "RemoteController": "On",
                "CPSController": "Idle",
                "OperatingMode": "Manual",
            },
            
            attack_requirements=["HackRF SDR", "SDR Software Tools", "60dB Attenuator"],
            
            attack_vectors=[
                BaseAttackVector(
                    name="GPS Signal Jamming via SDR",
                    signal=GPSAttackSignal(src=ExternalInput(), dst=GPSReceiver()),
                    required_access_level="Proximity",
                    configuration={
                        "frequency": "GPS L1",
                        "spoofing": False,
                        "jamming": True,
                        "duration": "Continuous",
                    },
                )
            ],
            
            attack_impacts=[
                BaseAttackImpact(
                    category="Denial of Service",
                    description="Rover cannot acquire valid GPS fix and therefore remains stationary, unable to initiate drive commands.",
                )
            ],
            
            exploit_steps=[
                "TA1 Exploit Steps",
                    "Use optical imaging tools and OCR to identify rover components, specifically GPS receiver module (U-Blox ZED-F9P).",
                    "Review firmware and data-sheets to confirm module vulnerability to GPS signal jamming.",
                    "Verify rover control logic requirement for a valid GPS fix before initiating any movement.",
                "TA2 Exploit Steps",
                    "Develop and validate a simulation model to determine precise frequency and power levels needed for effective GPS signal jamming.",
                    "Simulate GPS jamming scenario and confirm rover inability to acquire a GPS fix and initiate drive.",
                    "Fine-tune simulation parameters based on simulation outcomes.",
                "TA3 Exploit Steps",
                    "Install HackRF SDR and necessary software dependencies (e.g., gnuradio, multi-sdr-gps-sim).",
                    "Disconnect rover GPS antenna and directly connect SDR with a 60dB attenuator.",
                    "Power on rover and enable safety mechanism; connect computer to rover Wi-Fi network ('Arduino Wifi', password: 'TSWIZZLE1989').",
                    "Start SDR transmission using command: ./gps-sim --nav-fil brdc2550.24n --geo-loc 37.27097000,79.94143000,800 --radio hackrf --verbose.",
                    "Open rover's web interface at http://10.0.0.1 and attempt to initiate rover drive commands.",
                    "Verify rover does not start driving due to GPS signal unavailability.",
                    "Power off rover after confirming jamming effectiveness.",
            ],
            
            associated_files=[
                "GIGA-R1-firmware-model.docx",
                "brdc2550.24n",
                "command.txt",
            ],
            
            reference_urls=[
                "https://gpspatron.com/spoofing-a-multi-band-rtk-gnss-receiver-with-hackrf-one-and-gnss-jammer",
                "https://github.com/Mictronics/multi-sdr-gps-sim",
                "https://kaitlyn.guru/projects/spoofing-gps-with-an-sdr/",
                "https://github.com/senpai-on-fire/ngc2_taskboard/blob/main/CPVs/HII-NGP1AROV2ARR05-CPV008/HII-NGP1AROV2ARR05-CPV008-20250501.docx",
            ],
        )

    def in_goal_state(self, state: GlobalState):
        # Goal state: Rover has no valid GPS fix, and the motor is stationary, indicating successful GPS jamming.
        # return state.component_states[GPSReceiver].has_valid_fix == False and state.component_states[Motor].is_moving == False
        # TODO?
        pass
