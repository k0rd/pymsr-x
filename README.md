# pymsrx : A MSR605X Python Library

A comprehensive Python library for interacting with the MSR605X magnetic stripe card reader/writer. This library provides both low-level device control and high-level forensic analysis capabilities for magnetic stripe cards.

## Features

- **Full Device Control**: Complete implementation of MSR605X command set (reset, LED control, read/write operations, etc.)
- **Dual Mode Support**: Read and write in both ISO format and raw data mode
- **Forensic Analysis**: Advanced card data analysis including validation, pattern detection, and hashing
- **Card Type Detection**: Automatic identification of credit cards, gift cards, access cards, and hotel keys
- **Error Handling**: Robust error handling with custom exceptions for reliable operation
- **Cross-Platform**: Works on Windows, Linux, and macOS (with appropriate USB permissions)

## Installation

### Prerequisites

- Python 3.7+
- libusb (for USB communication)
- pyusb (`pip install pyusb`)

### Install the Library

```bash
pip install pymsrx
```

Or clone this repository and install manually:

```bash
git clone https://github.com/k0td/pymsrx.git
cd  pymsrx
pip install .
```

## Quick Start

```python
from pymsrx import MSR605X, CardData

# Connect to the device
with MSR605X() as msr:
    msr.connect()
    
    # Read a card
    card_data = msr.read_card()
    print(f"Track 1: {card_data.track1}")
    print(f"Track 2: {card_data.track2}")
    print(f"Track 3: {card_data.track3}")
    
    # Write to a card
    new_card = CardData(
        track1="%B1234567890123456^CARDHOLDER/NAME^24011230000000000000?",
        track2=";1234567890123456=24011230000000000000?"
    )
    msr.write_card(new_card)
```

## Usage Examples

### Basic Card Operations

```python
from pymsrx import MSR605X, CardData

# Initialize and connect
msr = MSR605X()
msr.connect()

# Get device info
print(f"Model: {msr.get_model()}")
print(f"Firmware: {msr.get_firmware_version()}")

# Control LEDs
msr.led("green", True)  # Turn on green LED
msr.led("red", False)   # Turn off red LED

# Set coercivity
msr.set_hico()  # Set to High Coercivity mode

# Read a card
card = msr.read_card()
if card:
    print(f"Track 1: {card.track1}")
    print(f"Track 2: {card.track2}")
    print(f"Track 3: {card.track3}")

# Write a card
new_card = CardData(
    track1="%B1234567890123456^CARDHOLDER/NAME^24011230000000000000?",
    track2=";1234567890123456=24011230000000000000?"
)
if msr.write_card(new_card):
    print("Card written successfully")

msr.close()
```

### Forensic Analysis

```python
from pymsrx import MSR605X

msr = MSR605X()
msr.connect()

# Get detailed forensic analysis
forensic_data = msr.forensic_read_card()
if forensic_data:
    print("Card Validation:")
    print(f"  Track 1: {forensic_data.validation['track1']}")
    print(f"  Track 2: {forensic_data.validation['track2']}")
    print(f"  Track 3: {forensic_data.validation['track3']}")
    
    print("\nData Hashes:")
    print(f"  Track 1 MD5: {forensic_data.hashes['track1']}")
    
    print("\nDetected Patterns:")
    print(f"  Credit Card: {forensic_data.patterns['track1']['credit_card']}")

# Generate comprehensive forensic report
report = msr.generate_forensic_report()
if report:
    print(f"Card Type: {report['card_type']}")
    print(f"Confidence: {report['confidence']}%")
    print(f"Anomalies: {report['anomalies']}")

msr.close()
```

### Advanced Configuration

```python
from pymsrx import MSR605X

msr = MSR605X()
msr.connect()

# Configure device settings
msr.set_bpi(1, 210)  # Set Track 1 to 210 BPI
msr.set_bpi(2, 75)   # Set Track 2 to 75 BPI
msr.set_bpi(3, 210)  # Set Track 3 to 210 BPI

msr.set_bpc(7, 5, 7)  # Set bits per character for tracks 1, 2, 3

msr.set_leading_zeros(61, 22)  # Set leading zeros for tracks

# Run diagnostics
if msr.ram_test():
    print("RAM test passed")

if msr.sensor_test():
    print("Sensor test passed")

msr.close()
```

## API Reference

### Main Classes

#### `MSR605X`
Main class for interacting with the MSR605X device.

**Key Methods:**
- `connect()`: Establish connection to the device
- `read_card(raw=False)`: Read card data (ISO or raw format)
- `write_card(card_data)`: Write data to a card
- `forensic_read_card()`: Read card with forensic analysis
- `get_model()`, `get_firmware_version()`: Get device information
- `led(which, on)`: Control device LEDs
- `set_hico()`, `set_loco()`: Set coercivity mode
- `set_bpi(track, density)`: Set bits per inch
- `set_bpc(t1_bits, t2_bits, t3_bits)`: Set bits per character
- `close()`: Close the device connection

#### `CardData`
Data class for storing card information.

**Attributes:**
- `track1`, `track2`, `track3`: Track data
- `raw`: Boolean indicating if data is in raw format

#### `ForensicCardData`
Extended card data with forensic information.

**Additional Attributes:**
- `hashes`: Dictionary of hash values for each track
- `validation`: Dictionary of validation results for each track
- `patterns`: Dictionary of detected patterns for each track

### Error Handling

The library provides custom exceptions for better error handling:

- `MSRError`: Base exception class
- `MSRCommunicationError`: Communication failures
- `MSRChecksumError`: Data checksum validation failures
- `MSRCardValidationError`: Card data validation failures

## Command Reference

The library implements all commands from the MSR605X programmer's manual:

|       Command         |          Method           |       Description        |
|-----------------------|---------------------------|--------------------------|
|    RESET              | `reset()`                 | Reset the device         |
|    READ               | `read_card()`             | Read card (ISO format)   |
|    WRITE              | `write_card()`            | Write card (ISO format)  |
|    Communication test | `ping()`                  | Test communication       |
|    LED control        | `led()`                   | Control device LEDs      |
|    Sensor test        | `sensor_test()`           | Test card sensor         |
|    RAM test           | `ram_test()`              | Test device RAM          |
|    Set leading zeros  | `set_leading_zeros()`     | Set leading zeros        |
|    Set BPI            | `set_bpi()`               | Set bits per inch        |
|    Set BPC            | `set_bpc()`               | Set bits per character   |
|    Set coercivity     | `set_hico()/set_loco()`   | Set Hi/Lo coercivity     |
|    Read raw           | `read_card(raw=True)`     | Read raw card data       |
|    Write raw          | `write_card(raw=True)`    | Write raw card data      |

## Troubleshooting

### Common Issues

1. **Device not found**: 
   - Ensure the device is properly connected and powered on
   - Check USB permissions (on Linux, you may need to add udev rules)

2. **Permission errors**:
   - On Linux, add your user to the `plugdev` group
   - Or create a udev rule for the device

3. **Track 3 data issues**:
   - The library includes special handling for track 3 data parsing
   - Ensure you're using the latest version of the library

### Debugging

Enable debug logging to see detailed communication with the device:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/k0rd/pymsrx.git`
3. Install development dependencies: `pip install -e .[dev]`
4. Make your changes and add tests
5. Run tests: `python -m pytest`
6. Submit a pull request

## License

This project is not licensed, you are not allowed to possess, make copies of, give, sell, or trade it. Exceptions are made in writing upon request. A written, hardcopy license must be stored on site with the software in order to use it or a derivitive work for a commercial or charitable (or otherwise non-private,non-personal) purpose. 
Licenses cannot be revoked, traded, assigned, or renewed. 

## Acknowledgments

- Based on the MSR605X Programmer's Manual
- Uses PyUSB for USB communication
- Inspired by various open source magnetic card reader projects

## Support

If you encounter any issues or have questions, please:
1. Check the troubleshooting section above
2. Search existing GitHub issues
3. Create a new issue with detailed information about your problem

## Disclaimer

This library is intended for legitimate purposes only. Always ensure you have proper authorization before reading or writing any magnetic stripe cards. The contributors are not responsible for misuse of this library.

## Housekeeping 

I wish I had found this and downloaded it so I didnt have to waste a beautiful section of the summer. That said, if you also appreciate this work, please consider making a small donation. Donations help me to independantly research and work on 1st world problems. Its a burden that I don't like to carry alone. If you feel like helping, please donate to the address below (or request my address for whatever coin you prefer to donate with). Thank you!

Bitcoin: bc1q6frpsylglmugt9yep5g8hlswpyzt0qdh6mw3qh
