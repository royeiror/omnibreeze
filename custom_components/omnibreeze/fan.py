import logging
import asyncio
from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.util.percentage import (
    percentage_to_ordered_list_item,
    ordered_list_item_to_percentage,
)
from .omni_api import OmniBreezeAPI
from .const import DOMAIN, CONF_IP, CONF_AUTH_KEY, DP_POWER, DP_OSCILLATION, DP_SPEED, DP_TEMP

_LOGGER = logging.getLogger(__name__)

SPEED_COUNT = 12
ORDERED_NAMED_FAN_SPEEDS = [str(i) for i in range(1, SPEED_COUNT + 1)]

async def async_setup_entry(hass, entry, async_add_entities):
    ip = entry.data[CONF_IP]
    auth_key = entry.data[CONF_AUTH_KEY]
    name = entry.title
    
    api = OmniBreezeAPI(ip, 6607, auth_key)
    fan = OmniBreezeFanEntity(api, name, entry.entry_id)
    async_add_entities([fan])
    
    # Try login
    if await api.async_login():
        _LOGGER.info("Successfully connected to OmniBreeze fan at %s", ip)
    else:
        _LOGGER.error("Failed to connect to OmniBreeze fan at %s", ip)

class OmniBreezeFanEntity(FanEntity):
    def __init__(self, api, name, entry_id):
        self._api = api
        self._name = name
        self._entry_id = entry_id
        self._attr_unique_id = f"omnibreeze_{entry_id}"
        self._attr_name = name
        self._state = False
        self._percentage = 0
        self._oscillating = False
        self._temperature = None
        
        self._api.on_state_update = self._handle_state_update

    @property
    def is_on(self):
        return self._state

    @property
    def percentage(self):
        return self._percentage

    @property
    def oscillating(self):
        return self._oscillating

    @property
    def supported_features(self):
        return FanEntityFeature.SET_SPEED | FanEntityFeature.OSCILLATE | FanEntityFeature.TURN_ON | FanEntityFeature.TURN_OFF

    def _handle_state_update(self, ttlv):
        _LOGGER.debug("State update received: %s", ttlv)
        for tid, val in ttlv:
            if tid == DP_POWER:
                self._state = bool(val)
            elif tid == DP_OSCILLATION:
                self._oscillating = bool(val)
            elif tid == DP_SPEED:
                self._percentage = ordered_list_item_to_percentage(ORDERED_NAMED_FAN_SPEEDS, str(val))
            elif tid == DP_TEMP:
                self._temperature = val
        self.async_write_ha_state()

    async def async_turn_on(self, percentage=None, preset_mode=None, **kwargs):
        await self._api.async_set_power(True)
        if percentage:
            await self.async_set_percentage(percentage)
        self._state = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs):
        await self._api.async_set_power(False)
        self._state = False
        self.async_write_ha_state()

    async def async_set_percentage(self, percentage):
        if percentage == 0:
            await self.async_turn_off()
            return
        speed = int(percentage_to_ordered_list_item(ORDERED_NAMED_FAN_SPEEDS, percentage))
        await self._api.async_set_speed(speed)
        self._percentage = percentage
        self.async_write_ha_state()

    async def async_oscillate(self, oscillating):
        await self._api.async_set_oscillation(oscillating)
        self._oscillating = oscillating
        self.async_write_ha_state()
