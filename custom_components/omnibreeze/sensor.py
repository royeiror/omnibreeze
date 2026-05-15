from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.const import UnitOfTemperature
from .const import DOMAIN, DP_TEMP

async def async_setup_entry(hass, entry, async_add_entities):
    # This is a bit of a hack since the API is shared with the fan
    # In a real integration, you'd use a DataUpdateCoordinator
    pass

class OmniBreezeTemperatureSensor(SensorEntity):
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_native_unit_of_measurement = UnitOfTemperature.CELSIUS

    def __init__(self, api, name, entry_id):
        self._api = api
        self._attr_name = f"{name} Temperature"
        self._attr_unique_id = f"omnibreeze_temp_{entry_id}"
        self._state = None

    @property
    def native_value(self):
        return self._state
