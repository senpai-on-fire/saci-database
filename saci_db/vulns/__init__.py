from .accelerometer_spoofing_vuln import AccelerometerSpoofingVuln
from .ardiscovery_flooding_vuln import ARDiscoveryFloodVuln
from .ardscovery_mitm_vuln import ARDiscoveryMitmVuln
from .ardscovery_overflow_vuln import ARDiscoveryOverflowVuln
from .barometer_spoofing_vuln import BarometerSpoofingVuln
from .compass_spoofing_vuln import CompassSpoofingVuln
from .control_loop_instability_vuln import ControlLoopInstabilityVuln
from .controller_integerity_vuln import ControllerIntegrityVuln
from .debug_interface_vuln import DebugInterfaceVuln
from .depthcamera_spoofing_vuln import DepthCameraSpoofingVuln
from .dxmx_jamming_vuln import DSMxJammingProtocolVuln
from .emergency_stop_vuln import EmergencyStopVuln
from .exposed_serial_connection_vuln import ExposedSerialConnectionVuln
from .gnss_spoofing_vuln import GNSSSpoofingVuln
from .gps_spoofing_vuln import GPSSpoofingVuln
from .gyroscope_spoofing_vuln import GyroscopeSpoofingVuln
from .icmp_flooding_vuln import IcmpFloodVuln
from .lack_beacon_filtering_vuln import LackBeaconFilteringVuln
from .lack_emi_controller_shielding_vuln import LackEMIControllerShieldingVuln
from .lack_emi_pwm_shielding_vuln import LackEMIPWMShieldingVuln
from .lack_emi_sensor_shielding_vuln import LackEMISensorShieldingVuln
from .lack_emi_serial_shielding_vuln import LackEMISerialShieldingVuln
from .lack_failsafe_disconnection_vuln import LackFailsafeDisconnectionVuln
from .lack_gnss_filtering_vuln import LackGNSSFilteringVuln
from .lack_gps_filtering_vuln import LackGPSFilteringVuln
from .lack_serial_auth_vuln import LackSerialAuthenticationVuln
from .lack_wifi_auth_vuln import LackWifiAuthenticationVuln
from .lack_wifi_encryption_vuln import LackWifiEncryptionVuln

# from .lidar_spoofing_vuln import LiDARSpoofingVuln
from .magnetometer_spoofing_vuln import MagnetometerSpoofingVuln
from .mavlink_mitm_vuln import MavlinkMitmVuln
from .mavlink_overflow_vuln import MavlinkOverflow
from .ml_adversarial_vuln import DeepNeuralNetworkVuln
from .navigation_control_failure_vuln import NavigationControlFailureVuln
from .noaps import NoAPSVuln
from .obstacle_avoidance_error_vuln import ObstacleAvoidanceErrorVuln
from .open_ftp_vuln import OpenFTPVuln
from .open_telnet_vuln import OpenTelnetVuln
from .opticalflow_spoofing_vuln import OpticalFlowSpoofingVuln
from .patch_misconfiguration_vuln import PatchMisconfigurationVuln
from .payload_firmware_vuln import FirmwarePayloadVuln
from .pwm_spoofing_vuln import PWMSpoofingVuln
from .rf_interference_vuln import RFInterferenceVuln
from .serial_spoofing_vuln import SerialSpoofingVuln
from .sik_flooding_vuln import SiKFloodingVuln
from .smbus_spoofing_vuln import SMBusVuln
from .speed_control_misbehavior_vuln import SpeedControlMisbehaviorVuln
from .stereo_matching_vuln import StereoMatchingVuln
from .unsecured_telemetry_vuln import UnsecuredTelemetryVuln
from .weak_application_auth_vuln import WeakApplicationAuthVuln
from .wifi_deauthentication_vuln import WiFiDeauthVuln
from .wifi_knowncreds_vuln import WifiKnownCredsVuln

__all__ = [
    "AccelerometerSpoofingVuln",
    "ARDiscoveryFloodVuln",
    "ARDiscoveryMitmVuln",
    "ARDiscoveryOverflowVuln",
    "BarometerSpoofingVuln",
    "CompassSpoofingVuln",
    "ControlLoopInstabilityVuln",
    "ControllerIntegrityVuln",
    "DebugInterfaceVuln",
    "DepthCameraSpoofingVuln",
    "DSMxJammingProtocolVuln",
    "DebugInterfaceVuln",
    "EmergencyStopVuln",
    "ExposedSerialConnectionVuln",
    "GNSSSpoofingVuln",
    "GPSSpoofingVuln",
    "GyroscopeSpoofingVuln",
    "IcmpFloodVuln",
    "LackBeaconFilteringVuln",
    "LackEMIControllerShieldingVuln",
    "LackEMIPWMShieldingVuln",
    "LackEMISensorShieldingVuln",
    "LackEMISerialShieldingVuln",
    "LackFailsafeDisconnectionVuln",
    "LackGNSSFilteringVuln",
    "LackGPSFilteringVuln",
    "LackSerialAuthenticationVuln",
    "LackWifiAuthenticationVuln",
    "LackWifiEncryptionVuln",
    # "LiDARSpoofingVuln",
    "MagnetometerSpoofingVuln",
    "MavlinkMitmVuln",
    "MavlinkOverflow",
    "DeepNeuralNetworkVuln",
    "NavigationControlFailureVuln",
    "NoAPSVuln",
    "ObstacleAvoidanceErrorVuln",
    "OpenFTPVuln",
    "OpenTelnetVuln",
    "OpticalFlowSpoofingVuln",
    "PatchMisconfigurationVuln",
    "FirmwarePayloadVuln",
    "PWMSpoofingVuln",
    "RFInterferenceVuln",
    "SerialSpoofingVuln",
    "SiKFloodingVuln",
    "SMBusVuln",
    "SpeedControlMisbehaviorVuln",
    "StereoMatchingVuln",
    "UnsecuredTelemetryVuln",
    "WeakApplicationAuthVuln",
    "WiFiDeauthVuln",
    "WifiKnownCredsVuln",
]
