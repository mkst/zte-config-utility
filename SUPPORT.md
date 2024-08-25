# Overview of support for ZTE routers

# Supported

| model             | type  | notes |
|-------------------|:-----:|-------|
| F600W             | **0** |       |
| ZTE F670L         |       |  See [gist](https://gist.github.com/zainarbani/723d1387bec9e1559de7a1029d08aa91) "Your key will be the ONT serial number (ZTEGXXXXXXXX, take only the last 8 hex characters in UPPERCASE) + MAC address of your ONT (from right to left)."
| ZTE ZXHN H268A V1 | **0** |       |
| ZXHN H108N V2.5   |       |       |
| ZXHN H168N V2.2   | **2** |       |
| ZXHN H168N V3.1   | **2** |       |
| ZXHN H168N V3.5   | **4** |       |
| ZXHN H188A        | **4** |       |
| ZXHN H267A V1.0   | **2** | @samtimber can extract username/password from `config.bin`|
| ZXHN H268Q        |       |       |
| ZXHN H288A        | **4** |       |
| ZXHN H298A        |       |       |
| ZXHN H298N        | **2** |       |
| ZXHN H298Q        | **4** |       |
| ZXV10 H201L V2.0  | **2** |       |

# Unsupported

The table below provides an overview of the various models that people have tried:

| model                 | type  |  support       | status                   | github issue(s) |
|-----------------------|:-----:|:--------------:|--------------------------|-----------|
| ZTE F450              |   ?   | :question:     | need example config.bin  | [#69](https://github.com/mkst/zte-config-utility/issues/69) |
| ZTE F670 V1.1         | **2** | :key:          | need more ivs/keys       | [#72](https://github.com/mkst/zte-config-utility/issues/72) |
| ZTE F670 V2.0 / F680  | **5** | :red_circle:   | `Unknown payload type 5` | [#57](https://github.com/mkst/zte-config-utility/issues/57) |
| ZTE F760              |   ?   | :question:     | need example config.bin  | [#54](https://github.com/mkst/zte-config-utility/issues/54) |
| ZTE H188A             |   ?   | :key:          | need more keys           | [#43](https://github.com/mkst/zte-config-utility/issues/43) |
| ZTE H3600 V9          |   ?   | :question:     | need example config.bin  | [#76](https://github.com/mkst/zte-config-utility/issues/76) |
| ZTE H388X(F)          |   ?   | :key:          | need more ivs/keys       | [#91](https://github.com/mkst/zte-config-utility/issues/91) |
| ZTE ZXHN F650         |   ?   | :question:     | need example config.bin  | [#28](https://github.com/mkst/zte-config-utility/issues/28) |
| ZTE ZXHN F671Y        |   ?   | :key:          | need more ivs/keys       | [#78](https://github.com/mkst/zte-config-utility/issues/78) |
| ZTE ZXHN F680         |   ?   | :red_circle:   | unsupported. `payload_type = 6` or `payload_type = 5`| [#15](https://github.com/mkst/zte-config-utility/issues/15), [#68](https://github.com/mkst/zte-config-utility/issues/68) |
| ZTE ZXHN H168A V2.0   |   4   | :key:          | need more ivs/keys       | [#25](https://github.com/mkst/zte-config-utility/issues/25) |
| ZTE ZXHN H199A        |   ?   | :question:     | need example config.bin  | [#67](https://github.com/mkst/zte-config-utility/issues/67) |
| ZTE ZXHN H267A V1.0   |   ?   | :white_circle: | supported?               | [#49](https://github.com/mkst/zte-config-utility/issues/49) |
| ZTE ZXHN H267N V1.1   |   ?   | :key:          | missing key(s)           | [#9](https://github.com/mkst/zte-config-utility/issues/9)   |
| ZTE ZXHN H268A V2.0   |   ?   | :red_circle:   | unsupported              | [#12](https://github.com/mkst/zte-config-utility/issues/12) |
| ZTE ZXHN H288A        |   ?   | :white_circle: | unknown                  | [#32](https://github.com/mkst/zte-config-utility/issues/32) |
| ZTE ZXHN H298A V1     |   ?   | :question:     | missing key(s)           | [#96](https://github.com/mkst/zte-config-utility/issues/96) |
| ZTE ZXHN H298A V9     |   ?   | :key:          | need more ivs/keys       | [#31](https://github.com/mkst/zte-config-utility/issues/31) |
| ZTE ZXHN H367A        |   ?   | :key:          | need more ivs/keys       | [#71](https://github.com/mkst/zte-config-utility/issues/71) |
| RT-GM-5               |   ?   | :key:          | need more ivs/keys       | [#41](https://github.com/mkst/zte-config-utility/issues/41) |
| Speedport Entry 2i    |   ?   | :white_circle: | externally supported, see [gist](https://gist.github.com/viliampucik/54956df2302362dab281f86178a4b848) | [#13](https://github.com/mkst/zte-config-utility/issues/13) |
| TIM Smart Hub+, H388X |   ?   | :key:          | need more ivs/keys       | [#24](https://github.com/mkst/zte-config-utility/issues/24) |

