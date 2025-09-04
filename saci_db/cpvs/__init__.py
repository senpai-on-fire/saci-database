from .cpv001_sik_mavlink_motors import MavlinkSiKCPV
from .cpv002_gps_spoofing_move import GPSSpoofingMoveCPV
from .cpv003_wifi_deauth_dos import WiFiDeauthDosCPV
from .cpv004_wifi_icmp_flooding import WiFiICMPFloodingCPV
from .cpv005_adv_ml_untrack import ObjectTrackCPV
from .cpv006_serial_motor_rollover import SerialRollOverCPV
from .cpv007_pmagnet_compass_dos import CompassPermanentSpoofingCPV
from .cpv008_wifi_webserver_crash import WifiWebCrashCPV
from .cpv009_gps_spoofing_static import GPSSpoofingStaticCPV
from .cpv010_depthcamera_spoofing_classic import ClassicDepthEstimationAttackCPV
from .cpv011_serial_motor_throttle import SerialThrottleCPV
from .cpv012_wifi_http_move import WifiWebMoveCPV
from .cpv013_gps_spoofing_loop import GPSSpoofingLoopCPV
from .cpv014_serial_arduino_control import SerialArduinoControlCPV
from .cpv015_wifi_http_stop import WifiWebStopCPV
from .cpv016_serial_motor_redirect import SerialRedirectCPV
from .cpv017_tmagnet_compass_disorient import CompassTemporarySpoofingCPV
from .cpv018_smbus_battery_shutdown import SMBusBatteryShutdownCPV
from .cpv019_debug_esc_flash import DebugESCFlashCPV
from .cpv020_serial_esc_bootloader import SerialESCBootloaderCPV
from .cpv021_serial_esc_reset import SerialESCResetCPV
from .cpv022_serial_esc_discharge import SerialESCDischargeCPV
from .cpv023_serial_esc_bufferoverflow import SerialESCOverflowCPV
from .cpv024_serial_esc_execcmd import SerialESCExeccmdCPV
from .cpv025_serial_motor_overheat import SerialOverheatingCPV
from .cpv026_acoustic_spoofing_accelerometer import AcousticSpoofingAccelerometerCPV
from .cpv027_acoustic_spoofing_gyroscope_dos import AcousticSpoofingGyroscopeCPV
from .cpv028_acoustic_spoofing_magnetometer import AcousticSpoofingMagnetometerCPV
from .cpv029_airflow_barometer_spoofing import BarometricSensorSpoofingCPV
from .cpv030_projector_opticalflow_spoofing import ProjectorOpticalFlowCPV
from .cpv031_depthcamera_spoofing_ml import MLDepthEstimationAttackCPV
from .cpv032_emi_motor_block import EMIMotorBlockCPV
from .cpv033_wifi_deauth_quad import WiFiDeauthQuadDosCPV
from .cpv034_wifi_mavlink_disarm import MavlinkDisarmCPV
from .cpv035_emi_motor_control import EMIMotorFullControlCPV
from .cpv036_emi_motor_rotate import EMIMotorBlockRotateCPV
from .cpv037_wifi_ardiscovery_flooding import ARDiscoveryDoSCPV
from .cpv038_wifi_ardiscovery_overflow import ARDiscoveryBufferOverflowCPV
from .cpv039_wifi_ardisovery_mitm import ARDiscoveryMitM
from .cpv040_ftp_telnet_Hijack import FTPTelnetHijackCPV
from .cpv041_wifi_beacon_flooding import BeaconFrameFloodingCPV
from .cpv042_rf_signal_jamming import RFJammingCPV
from .cpv043_emi_spoofing_magnetometer import EMISpoofingMagnetometerCPV
from .cpv044_emi_comm_gyroscope import GyroscopeEMIChannelDisruptionCPV
from .cpv045_emi_comm_accelerometer import AccelerometerEMIChannelDisruptionCPV
from .cpv046_emi_comm_magnetometer import MagnetometerEMIChannelDisruptionCPV
from .cpv047_gps_directional_manipulation import DirectionalManipulationCPV
from .cpv048_gps_failsafe_avoidance import FailSafeAvoidanceCPV
from .cpv049_gps_path_manipulation import PathManipulationCPV
from .cpv050_patch_emergency_stop_failure import PatchEmergencyStopFailureCPV
from .cpv051_patch_turn_malfunction import PatchPivotTurnMalfunctionCPV
from .cpv052_patch_unstable_attitude_control import PatchUnstableAttitudeControlCPV
from .cpv053_patch_mission_failure import PatchMissionFailureCPV
from .cpv054_patch_obstacle_avoidance_error import PatchObstacleAvoidanceErrorCPV
from .cpv055_gnss_spoofing_flight import GNSSFlightModeSpoofingCPV
from .cpv056_gnss_spoofing_loiter import GNSSLoiterModeSpoofingCPV
from .cpv057_dsmx_jamming_hijack import DSMxJammingHijackCPV
from .cpv058_payload_command_crash import PayloadCrashCommandCPV
from .cpv059_payload_disable_safety import PayloadDisableSafetyCPV
from .cpv060_payload_spoof_id import PayloadSpoofDroneIDCPV
from .cpv061_serial_motor_tone import SerialToneCPV
from .cpv062_lidar_perception_manipulation import LiDARPerceptionManipulationCPV
from .cpv063_lidar_sensor_denial import LiDARSensorDenialCPV
from .cpv064_adv_ml_misnavigation import MLMisnavigationCPV
from .cpv065_adv_ml_undetect import AdvMLUndetectCPV
from .cpv066_optflow_spoof_misguidance import CPV066_OptflowSpoofMisguidance
from .cpv067_laser_perception_denial import LaserVisionAttackCPV
from .cpv068_acoustic_spoofing_airspeed import AcousticSpoofingAirspeedCPV
from .cpv069_backpack_firmware_overwrite import BackpackFirmwareOverwriteCPV
from .cpv070_flight_parameters_rewrite import FlightParametersRewriteCPV
from .cpv071_barometer_airflow_blocking import BarometerObstructionCPV
from .cpv072_rf_signal_blocking import RFBlockingCPV
from .cpv073_motor_parameters_rewrite import RC3ParameterManipulationCPV
from .cpv074_flip_command_inject import FlipAtLowAltitudeCPV
from .cpv075_throttle_command_inject import RCMotorJitterCPV
from .cpv076_attitude_control_rewrite import AttitudeFlipParameterManipulation
from .cpv077_wifi_disconnect_firmware_flash import ArduinoGigaFirmwareOverwriteCPV
from .cpv078_wifi_modifty_firmware_flash import ArduinoUnoFirmwareOverwriteCPV
from .cpv079_lidar_spoofing_mirroring import LiDARBYPASSMirrorCPV
from .cpv080_lidar_spoofing_laser import LiDARSpoofingStopCPV
from .cpv081_passthrough_binary_stop import GPSPassthroughStopCPV
from .cpv082_gps_signal_jamming import GPSJammingNoDriveCPV
from .cpv083_lidar_data_corrupt import LiDARDataDesynchronization
from .cpv084_lidar_spoofing_modulation import LiDARSpoofingModulation
from .cpv085_emi_interference_cabling import EMIPowerCableMagnetometerCPV
from .cpv086_can_messages_delay import CANMessagesDelayCPV
from .cpv087_usb_cable_unplug import UsbCableUnplugCPV
from .cpv088_http_flood_control import WifiWebCrashCPV
from .cpv089_lidar_light_absorb import LiDARLightAbsorbCPV

CPVS = [
    MavlinkSiKCPV(),
    GPSSpoofingMoveCPV(),
    WiFiDeauthDosCPV(),
    WiFiICMPFloodingCPV(),
    ObjectTrackCPV(),
    SerialRollOverCPV(),
    CompassPermanentSpoofingCPV(),
    WifiWebCrashCPV(),
    GPSSpoofingStaticCPV(),
    ClassicDepthEstimationAttackCPV(),
    SerialThrottleCPV(),
    WifiWebMoveCPV(),
    GPSSpoofingLoopCPV(),
    SerialArduinoControlCPV(),
    WifiWebStopCPV(),
    SerialRedirectCPV(),
    CompassTemporarySpoofingCPV(),
    SMBusBatteryShutdownCPV(),
    DebugESCFlashCPV(),
    SerialESCBootloaderCPV(),
    SerialESCResetCPV(),
    SerialESCDischargeCPV(),
    SerialESCOverflowCPV(),
    SerialESCExeccmdCPV(),
    SerialOverheatingCPV(),
    AcousticSpoofingAccelerometerCPV(),
    AcousticSpoofingGyroscopeCPV(),
    AcousticSpoofingMagnetometerCPV(),
    BarometricSensorSpoofingCPV(),
    ProjectorOpticalFlowCPV(),
    MLDepthEstimationAttackCPV(),
    EMIMotorBlockCPV(),
    WiFiDeauthQuadDosCPV(),
    MavlinkDisarmCPV(),
    EMIMotorFullControlCPV(),
    EMIMotorBlockRotateCPV(),
    ARDiscoveryDoSCPV(),
    ARDiscoveryBufferOverflowCPV(),
    ARDiscoveryMitM(),
    FTPTelnetHijackCPV(),
    BeaconFrameFloodingCPV(),
    RFJammingCPV(),
    EMISpoofingMagnetometerCPV(),
    GyroscopeEMIChannelDisruptionCPV(),
    AccelerometerEMIChannelDisruptionCPV(),
    MagnetometerEMIChannelDisruptionCPV(),
    DirectionalManipulationCPV(),
    FailSafeAvoidanceCPV(),
    PathManipulationCPV(),
    PatchEmergencyStopFailureCPV(),
    PatchPivotTurnMalfunctionCPV(),
    PatchUnstableAttitudeControlCPV(),
    PatchMissionFailureCPV(),
    PatchObstacleAvoidanceErrorCPV(),
    GNSSFlightModeSpoofingCPV(),
    GNSSLoiterModeSpoofingCPV(),
    DSMxJammingHijackCPV(),
    PayloadCrashCommandCPV(),
    PayloadDisableSafetyCPV(),
    PayloadSpoofDroneIDCPV(),
    SerialToneCPV(),
    LiDARPerceptionManipulationCPV(),
    LiDARSensorDenialCPV(),
    MLMisnavigationCPV(),
    AdvMLUndetectCPV(),
    CPV066_OptflowSpoofMisguidance(),
    LaserVisionAttackCPV(),
    AcousticSpoofingAirspeedCPV(),
    BackpackFirmwareOverwriteCPV(),
    FlightParametersRewriteCPV(),
    BarometerObstructionCPV(),
    RFBlockingCPV(),
    RC3ParameterManipulationCPV(),
    FlipAtLowAltitudeCPV(),
    RCMotorJitterCPV(),
    AttitudeFlipParameterManipulation(),
    ArduinoGigaFirmwareOverwriteCPV(),
    ArduinoUnoFirmwareOverwriteCPV(),
    LiDARBYPASSMirrorCPV(),
    LiDARSpoofingStopCPV(),
    GPSPassthroughStopCPV(),
    GPSJammingNoDriveCPV(),
    LiDARDataDesynchronization(),
    LiDARSpoofingModulation(),
    EMIPowerCableMagnetometerCPV(),
    CANMessagesDelayCPV(),
    UsbCableUnplugCPV(),
    LiDARLightAbsorbCPV(),
]