# OmniBreeze Fan for Home Assistant

Custom component for OmniBreeze tower fans. This integration provides local control over your Wi-Fi enabled fans.

## Features
- Power control
- Fan speed (1-12)
- Oscillation control
- Temperature sensor

## Installation

### HACS (Recommended)
1. In Home Assistant, go to **HACS > Integrations**.
2. Click the three dots in the top right corner and select **Custom repositories**.
3. Paste the URL of this repository: `https://github.com/yourusername/omnibreeze`
4. Select **Integration** as the category and click **Add**.
5. Find the **OmniBreeze Fan** integration and click **Download**.
6. Restart Home Assistant.

### Manual
1. Download the `custom_components/omnibreeze` folder from this repository.
2. Copy it into your Home Assistant's `custom_components` directory.
3. Restart Home Assistant.

## Configuration
1. Go to **Settings > Devices & Services**.
2. Click **Add Integration** and search for **OmniBreeze**.
3. Enter the **IP Address** and **Auth Key** for your fan.

## Finding the Auth Key
The Auth Key is a 16-byte base64 encoded string required for encryption. It can be found in the `mmkv.default` file of the Wonderfree Android app on a rooted device.
