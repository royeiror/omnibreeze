import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
import homeassistant.helpers.config_validation as cv
from .const import DOMAIN, CONF_IP, CONF_AUTH_KEY

class OmniBreezeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}
        if user_input is not None:
            await self.async_set_unique_id(user_input[CONF_IP])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title=f"Fan {user_input[CONF_IP]}", data=user_input)

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema({
                vol.Required(CONF_IP): str,
                vol.Required(CONF_AUTH_KEY): str,
            }),
            errors=errors,
        )
