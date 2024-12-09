from .ngcrover import NGCRover
from .px4_quadcopter_device import PX4Quadcopter
from .gs_quadcopter import GSQuadcopter

devices = {
    "ngcrover": NGCRover(),
    "px4quadcopter": PX4Quadcopter(),
    "gsquadcopter": GSQuadcopter(),
}