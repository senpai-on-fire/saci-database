from saci.modeling.communication import AuthenticatedCommunication
from saci.modeling.device import TelemetryHigh, TelemetryAlgorithmic, Telemetry, CyberComponentSourceCode, CyberComponentBinary
from saci.modeling.device.component.cyber.cyber_abstraction_level import CyberAbstractionLevel


class GCSTelemetryHigh(TelemetryHigh):
    def __init__(self):
        super().__init__(name="gcs_telemetry_high", protocol_name="mavlink")


class GCSTelemetryAlgo(TelemetryAlgorithmic):
    def __init__(self, system_id=None):
        super().__init__(name="gcs_telemetry_algo")
        self.system_id = system_id

    def accepts_communication(self, communication: AuthenticatedCommunication) -> bool:
        if communication.identifier == self.system_id:
            return True


class GCSTelemetry(Telemetry):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: GCSTelemetryHigh(),
            CyberAbstractionLevel.ALGORITHMIC: GCSTelemetryAlgo(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
