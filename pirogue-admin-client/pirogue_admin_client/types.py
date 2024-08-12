from enum import Enum


class OperatingMode(Enum):
    UNSPECIFIED = 0
    ACCESS_POINT = 1
    APPLIANCE = 2
    VPN = 3
    WIFI_2_USB_TETHERING = 4

    def __str__(self) -> str:
        return f'{self.name}'
