<div align="center">

[English](../../README.md) · **Español**

# zte config utility

Crea binarios byte por byte idénticos para la cantidad limitada de archivos `config.bin`  que han sido probados.

El núcleo del trabajo de decodificación se ha tomado de un volcado de [pastebin](https://pastebin.com/GGxbngtK) por 'Felis-Sapien'.

</div>

## Inicio rápido

Clona el repositorio y ejecuta `python3 -m pip install . --user` para instalar el módulo `zcu`.
Después, puede utilizar los scripts del directorio [examples](./examples).

**NOTA:** Este proyecto solo se ha probado con **Python 3.7** o versiones superiores.

### Decodificación 100% automática

Intenta ejecutar `examples/auto.py` con tu archivo  `config.bin`

```sh
$ python3 examples/auto.py config.bin config.xml
```

## Ejemplos

### Decodificar/Codificar un tipo-2, versión 2 `config.bin` (si se conoce la clave para la firma proporcionada/detectada, es posible omitirla)

```sh
$ python3 examples/decode.py resources/ZXHN_H298N.bin resources/ZXHN_H298N.xml --key 'Wj'
$ python3 examples/encode.py resources/ZXHN_H298N.xml resources/ZXHN_H298N.NEW.bin --key 'Wj' --signature 'ZXHN H298N' --include-header
$ md5sum resources/ZXHN_H298N.bin resources/ZXHN_H298N.NEW.bin
8529c1e3d4e3018db508a3b5b5b574cc  resources/ZXHN_H298N.bin
8529c1e3d4e3018db508a3b5b5b574cc  resources/ZXHN_H298N.NEW.bin
```

### Decodificar/Codificar un tipo-2, versión 1 `config.bin`

```sh
$ python3 examples/decode.py resources/ZXHN_H108N_V2.5.bin resources/ZXHN_H108N_V2.5.xml --key 'GrWM2Hz&LTvz&f^5'
$ python3 examples/encode.py resources/ZXHN_H108N_V2.5.xml resources/ZXHN_H108N_V2.5.NEW.bin --key 'GrWM2Hz&LTvz&f^5' --signature 'ZXHN H108N V2.5' --version 1 --include-header
$ md5sum resources/ZXHN_H108N_V2.5.bin resources/ZXHN_H108N_V2.5.NEW.bin
5dbb537bb8a5bfa51f9bc9e2d48f576d  resources/ZXHN_H108N_V2.5.bin
5dbb537bb8a5bfa51f9bc9e2d48f576d  resources/ZXHN_H108N_V2.5.NEW.bin
```

### Decodificar/Codificar un tipo-0 `config.bin`

```sh
$ python3 examples/decode.py resources/F600W.bin resources/F600W.xml
$ python3 examples/encode.py resources/F600W.xml resources/F600W.NEW.bin --signature F600W --payload-type 0
$ md5sum resources/F600W.bin resources/F600W.NEW.bin
a6ac0e5e04f705b54747c30f80dfd4ba  resources/F600W.bin
a6ac0e5e04f705b54747c30f80dfd4ba  resources/F600W.NEW.bin
```

### Decodificar/Codificar un tipo-3 `db_default_auto_cfg.xml` de un H298Q

```sh
$ python3 examples/decode.py --model "H298Q" resources/ZXHN_H298Q_C7_db_type3.bin resources/ZXHN_H298Q_C7_db.xml
$ python3 examples/encode.py --model "H298Q" resources/ZXHN_H298Q_C7_db.xml resources/ZXHN_H298Q_C7_db_type3.NEW.bin
$ md5sum resources/ZXHN_H298Q_C7_db_type3.bin resources/ZXHN_H298Q_C7_db_type3.NEW.bin
2b76e781a8a91136539e0f2534ac030b  resources/ZXHN_H298Q_C7_db_type3.bin
2b76e781a8a91136539e0f2534ac030b  resources/ZXHN_H298Q_C7_db_type3.NEW.bin
```

### Decodificar/Codificar `config.bin` de un router DigiMobil ZXHN H298A

Puedes encontrar el número de serie en la interfaz web del router, en la pestaña "Gestión y diagnóstico".

```sh
$ python3 examples/decode.py --serial ZTEXXXXXXXXXXXX config.bin config.xml
$ python3 examples/encode.py --serial ZTEXXXXXXXXXXXX --signature 'ZXHN H298A V1.0' config.xml config.bin
```

### Decodificar/Codificar `config.bin` de un router ZXHN H168N V3.5

Algunos routers (Tipo 4), podrían utilizar la firma para crear la clave de cifrado.
Al realizar la decodificación, ZCU utilizará automáticamente la firma que encuentre (sin espacios), pero puedes especificar una pasando el argumento `--signature` al script `decode.py`.
Al volver a codificar, debes especificar `--use-signature-encryption` si deseas que se utilice el cifrado de firmas.

```sh
$ python3 examples/decode.py ./config.bin ./config.xml
$ python3 examples/encode.py --signature 'ZXHN H168N V3.5' --use-signature-encryption config.xml config.bin
```

### Decodificar/Codificar archivos `config.bin` de Tipo-4 específicos del dispositivo de routers de la familia H288A

Algunas configuraciones de Tipo-4 utilizan datos TagParams específicos del dispositivo, en lugar de una clave estática basada únicamente en una firma.
Para esas configuraciones, proporciona la firma del router junto con la dirección MAC, el número de serie y la contraseña larga provenientes de la entrada `4100` de `TagParams`.
Esto solo funciona si conoces los valores específicos de cada dispositivo para ese router.

```sh
$ python3 examples/decode.py --signature H288A --serial ZTEGC0DE1234 --mac 00:11:22:33:44:55 --longpass deadbeefdeadbeef config.bin config.xml
$ python3 examples/encode.py --signature H288A --serial ZTEGC0DE1234 --mac 00:11:22:33:44:55 --longpass deadbeefdeadbeef config.xml config.bin
```

Los modelos H188A/H288A también cuentan con variantes de Tipo-4 derivadas de la firma. Para estas, utilice `--signature ... --use-signature-encryption` al realizar la recodificación.

### Extraer la 'firma' de un `config.bin`

```sh
$ python3 examples/signature.py resources/ZXHN_H108N_V2.5.bin
ZXHN H108N V2.5
```

### Autodecodificación

Si la firma de tu router está asociada a una clave conocida por esta utilidad, puedes omitir el parámetro `--key` al realizar la decodificación.

```sh
$ python3 examples/decode.py resources/ZXHN_H298N.bin resources/ZXHN_H298N.xml
```

También puedes probar todas las claves conocidas por esta utilidad en tu archivo `config.bin` mediante el parámetro `--try-all-known-keys`.
Esto puede resultar útil si tu clave es conocida, pero la firma de tu router no se ha asociado a ella.

```sh
$ python3 examples/decode.py resources/ZXHN_H298N.bin resources/ZXHN_H298N.xml --try-all-known-keys
```

## Limitaciones

El decodificador solo se ha probado con archivos `config.bin` generados por los siguientes routers:
 - `ZXHN H298A`
 - `ZXHN H298N`
 - `ZXHN H267A`
 - `ZXHN H268Q`
 - `ZXHN H298Q`
 - `ZXHN H168N V2.2`
 - `ZXHN H168N V3.5`
 - `ZXHN H108N V2.5`
 - `F600W`
 - `ZXHN F680 V6.0`

Y archivos `db_default_auto_cfg.xml` extraídos de los firmwares de `ZXHN H268N` y `ZXHN H298Q`

Debido a esto, se parte de una serie de suposiciones. El codificador no ha sido sometido a pruebas exhaustivas en entornos reales. Úselo bajo su propia responsabilidad.

## Requisitos

El cifrado AES se basa en [pycryptodomex](https://pypi.org/project/pycryptodomex/).
