from saci.modeling import BaseVulnerability
from saci.modeling.device import GyroscopeHigh, GyroscopeSource, GyroscopeAlgorithmic, Device
from saci.modeling.communication import BaseCommunication


class RockingDronesVuln(BaseVulnerability):
    def __init__(self):
        super().__init__(
            component=GyroscopeAlgorithmic,
            _input=None, # Input can be redefined by the attacker 
            output=BaseCommunication(), # TODO: still need to express how this sensor connects with other components
        )

    def exists(self, device: Device) -> bool:
        for comp in device.components:
            if isinstance(comp, GyroscopeHigh) and comp.chip_type == "MEMS":
                return True

            if isinstance(comp, GyroscopeAlgorithmic):
                vuln_sensor_list = ['L3G4200D', 'L3GD20', 'LSM330', 'LPR5150AL', 'LPY503AL', 'MPU3050', 'MPU6000', 'MPU6050', 'MPU6500', 'MPU9150', 'IMU3000', 'ITG3200', 'IXZ650', 'ADXRS610', 'ENC-03MB']
                if comp.chip_name in vuln_sensor_list:
                    return True
            
            if isinstance(comp, GyroscopeSource):
                vuln_frequencies = (680, 30_000) # Estimate of frequencies that could be used to rock the drone (680 Hz is the minimum frequency for a 0.5m drone, 30kHz is the max that a MEMS gyroscope can handle)
                if min(vuln_frequencies) <= comp.harmonic_frequency <= max(vuln_frequencies):
                    return True