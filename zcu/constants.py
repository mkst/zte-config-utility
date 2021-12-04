"""Magic number constants from ZTE routers"""

PAYLOAD_MAGIC = 0x01020304
SIGNATURE_MAGIC = 0x04030201
ZTE_MAGIC = (0x99999999, 0x44444444, 0x55555555, 0xAAAAAAAA)

# type 4 encryption, using serial for key/iv (digimobil)
DIGIMOBIL_BASE_KEY = "8cc72b05705d5c46"
DIGIMOBIL_BASE_IV = "667b02a85c61c786"

# type 4 encryption, using signature for key/iv
T4_SIGN_BASE_KEY = "Key02721401"
T4_SIGN_BASE_IV = "Iv02721401"
