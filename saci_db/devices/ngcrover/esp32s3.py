from saci.modeling.communication.auth_comm import AuthenticatedCommunication
from saci.modeling.device.component.cyber.cyber_abstraction_level import (
    CyberAbstractionLevel,
)
from saci.modeling.device.component.cyber import (
    CyberComponentSourceCode,
    CyberComponentBinary,
)
from saci.modeling.device.telemetry import (
    Telemetry,
    TelemetryHigh,
    TelemetryAlgorithmic,
)


class ESP32S3WifiTelemetry(Telemetry):
    """
    Describes Sik radio.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ABSTRACTIONS = {
            CyberAbstractionLevel.HIGH: TelemetryHigh(
                name="ESP32S3 Wifi",
                protocol_name="wifi",
                communication=AuthenticatedCommunication(),
            ),
            CyberAbstractionLevel.ALGORITHMIC: TelemetryAlgorithmic(),
            CyberAbstractionLevel.SOURCE: CyberComponentSourceCode(),
            CyberAbstractionLevel.BINARY: CyberComponentBinary(),
        }
