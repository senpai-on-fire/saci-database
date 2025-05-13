from .cpv010_depthcamera_spoofing_classic import *
from .cpv011_serial_motor_throttle import *
from .cpv012_wifi_http_move import *
from .cpv013_gps_spoofing_loop import *
from .cpv014_serial_arduino_control import *
from .cpv015_wifi_http_stop import *
from .cpv016_serial_motor_redirect import *
from .cpv061_serial_motor_tone import *
from .cpv017_tmagnet_compass_disorient import *
from .cpv018_smbus_battery_shutdown import *
from .cpv019_debug_esc_flash import *
from .cpv001_sik_mavlink_motors import *
from .cpv020_serial_esc_bootloader import *
from .cpv021_serial_esc_reset import *
from .cpv022_serial_esc_discharge import *
from .cpv023_serial_esc_bufferoverflow import *
from .cpv024_serial_esc_execcmd import *
from .cpv025_serial_motor_overheat import *
from .cpv026_acoustic_spoofing_accelerometer import *
from .cpv027_acoustic_spoofing_gyroscope_dos import *
from .cpv028_acoustic_spoofing_magnetometer import *
from .cpv029_airflow_barometer_spoofing import *
from .cpv002_gps_spoofing_move import *
from .cpv030_projector_opticalflow_spoofing import *
from .cpv031_depthcamera_spoofing_ml import *
from .cpv032_emi_motor_block import *
from .cpv033_wifi_deauth_quad import *
from .cpv034_wifi_mavlink_disarm import *
from .cpv035_emi_motor_control import *
from .cpv036_emi_motor_rotate import *
from .cpv037_wifi_ardiscovery_flooding import *
from .cpv038_wifi_ardiscovery_overflow import *
from .cpv039_wifi_ardisovery_mitm import *
from .cpv003_wifi_deauth_dos import *
from .cpv040_ftp_telnet_Hijack import *
from .cpv041_wifi_beacon_flooding import *
from .cpv042_rf_signal_jamming import *
from .cpv043_emi_spoofing_magnetometer import *
from .cpv044_emi_comm_gyroscope import *
from .cpv045_emi_comm_accelerometer import *
from .cpv046_emi_comm_magnetometer import *
from .cpv047_gps_directional_manipulation import *
from .cpv048_gps_failsafe_avoidance import *
from .cpv049_gps_path_manipulation import *
from .cpv004_wifi_icmp_flooding import *
from .cpv050_patch_emergency_stop_failure import *
from .cpv051_patch_turn_malfunction import *
from .cpv052_patch_unstable_attitude_control import *
from .cpv053_patch_mission_failure import *
from .cpv054_patch_obstacle_avoidance_error import *
from .cpv055_gnss_spoofing_flight import *
from .cpv056_gnss_spoofing_loiter import *
from .cpv057_dsmx_jamming_hijack import *
from .cpv058_payload_command_crash import *
from .cpv059_payload_disable_safety import *
from .cpv005_adv_ml_untrack import *
from .cpv060_payload_spoof_id import *
from .cpv006_serial_motor_rollover import *
from .cpv007_pmagnet_compass_dos import *
from .cpv008_wifi_webserver_crash import *
from .cpv009_gps_spoofing_static import *
from .cpv061_serial_motor_tone import *


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
    SerialThrottleCPV(),
    WifiWebMoveCPV(),
    GPSSpoofingLoopCPV(),
    SerialArduinoControlCPV(),
    WifiWebStopCPV(),
    SerialRedirectCPV(),
    SerialToneCPV(),
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
    ClassicDepthEstimationAttackCPV(),
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
    PayloadSpoofDroneIDCPV()
]