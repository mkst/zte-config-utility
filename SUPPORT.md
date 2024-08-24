# Overview of support for ZTE routers

# Supported

| model | notes |
| ----- | ----- |
| ZXHN H298A |
| ZXHN H298N |
| ZXHN H267A | @samtimber can extract username/password from config.bin |
| ZXHN H268Q |
| ZXHN H298Q |
| ZXHN H168N V2.2 |
| ZXHN H168N V3.5 |
| ZXHN H108N V2.5 |
| F600W |
| ZTE F670L | See [gist](https://gist.github.com/zainarbani/723d1387bec9e1559de7a1029d08aa91) "Your key will be the ONT serial number (ZTEGXXXXXXXX, take only the last 8 hex characters in UPPERCASE) + MAC address of your ONT (from right to left)."

# Unsupported

The table below shows an overview of the various models that people have tried:

| model | github issue(s) | supported? | status |
|-|-|:-:|-|
| ZTE F450              | [#69](https://github.com/mkst/zte-config-utility/issues/69) | :question:     | unknown |
| ZTE F670 V1.1         | [#72](https://github.com/mkst/zte-config-utility/issues/72) | :white_circle: | missing key(s) |
| ZTE F670 V2.0 / F680  | [#57](https://github.com/mkst/zte-config-utility/issues/57) | :red_circle:   | `Unknown payload type 5` |
| ZTE F760              | [#54](https://github.com/mkst/zte-config-utility/issues/54) | :question:     | unknown |
| ZTE H188A             | [#43](https://github.com/mkst/zte-config-utility/issues/43) | :black_circle: | missing key(s) |
| ZTE H3600 V9          | [#76](https://github.com/mkst/zte-config-utility/issues/76) | :red_circle:   | ValueError: Payload header does not start with the payload magic. |
| ZTE H3600 V9          | [#94](https://github.com/mkst/zte-config-utility/issues/94) | :question:     | unknown |
| ZTE H388X(F)          | [#91](https://github.com/mkst/zte-config-utility/issues/91) | :white_circle: | missing key(s) |
| ZTE ZXHN F650         | [#28](https://github.com/mkst/zte-config-utility/issues/28) | :question:     | unknown |
| ZTE ZXHN F671Y        | [#78](https://github.com/mkst/zte-config-utility/issues/78) | :red_circle:   | `header[2]` is not 4. |
| ZTE ZXHN F680         | [#15](https://github.com/mkst/zte-config-utility/issues/15), [#68](https://github.com/mkst/zte-config-utility/issues/68) | :red_circle:   | unsupported. `payload_type = 6` or `payload_type = 5`|
| ZTE ZXHN H168A V2.0   | [#25](https://github.com/mkst/zte-config-utility/issues/25) | :white_circle: | missing key(s) |
| ZTE ZXHN H199A        | [#67](https://github.com/mkst/zte-config-utility/issues/67) | :question:     | unknown |
| ZTE ZXHN H267A V1.0   | [#49](https://github.com/mkst/zte-config-utility/issues/49) | :white_circle: | supported? |
| ZTE ZXHN H267N V1.1   | [#9](https://github.com/mkst/zte-config-utility/issues/9)   | :black_circle: | missing key(s)  |
| ZTE ZXHN H268A V2.0   | [#12](https://github.com/mkst/zte-config-utility/issues/12) | :red_circle:   | unsupported |
| ZTE ZXHN H288A        | [#32](https://github.com/mkst/zte-config-utility/issues/32) | :white_circle: | unknown |
| ZTE ZXHN H298A V1     | [#96](https://github.com/mkst/zte-config-utility/issues/96) | :red_circle:   | ValueError: Payload header does not start with the payload magic.
| ZTE ZXHN H298A V9     | [#31](https://github.com/mkst/zte-config-utility/issues/31) | :white_circle: | missing key(s) |
| ZTE ZXHN H367A        | [#71](https://github.com/mkst/zte-config-utility/issues/71) | :white_circle: | missing key(s) |
| RT-GM-5               | [#41](https://github.com/mkst/zte-config-utility/issues/41) | :white_circle: | missing key(s) |
| Speedport Entry 2i    | [#13](https://github.com/mkst/zte-config-utility/issues/13) | :white_circle: | externally supported, see [gist](https://gist.github.com/viliampucik/54956df2302362dab281f86178a4b848) |
| TIM Smart Hub+, H388X | [#24](https://github.com/mkst/zte-config-utility/issues/24) | :white_circle: | missing key(s) |

