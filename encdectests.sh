python3 examples/decode.py resources/db_default_auto_cfg.bin resources/db_default_auto_cfg.xml2
python3 examples/encode.py --chunk-size 8192 resources/db_default_auto_cfg.xml resources/db_default_auto_cfg.bin2

python3 examples/decode.py resources/ZXHN_H298Q_C7_db_type0.bin resources/ZXHN_H298Q_C7_db.xml2
python3 examples/decode.py --try-all-known-keys resources/ZXHN_H298Q_C7_db_type3.bin resources/ZXHN_H298Q_C7_db.xml3
python3 examples/encode.py resources/ZXHN_H298Q_C7_db.xml resources/ZXHN_H298Q_C7_db_type0.bin2
python3 examples/encode.py --model "H298Q" resources/ZXHN_H298Q_C7_db.xml resources/ZXHN_H298Q_C7_db_type3.bin2

python3 examples/decode.py resources/F600W.bin resources/F600W.xml2
python3 examples/encode.py --signature "F600W" resources/F600W.xml resources/F600W.bin2

python3 examples/decode.py resources/ZXHN_H108N_V2.5.bin resources/ZXHN_H108N_V2.5.xml2
python3 examples/encode.py --signature "ZXHN H108N V2.5" --version 1 resources/ZXHN_H108N_V2.5.xml resources/ZXHN_H108N_V2.5.bin2

python3 examples/decode.py resources/ZXHN_H168N_V3.1.bin resources/ZXHN_H168N_V3.1.xml2
python3 examples/encode.py --signature "ZXHN H168N V3.1" --include-unencrypted-length resources/ZXHN_H168N_V3.1.xml resources/ZXHN_H168N_V3.1.bin2

python3 examples/decode.py resources/ZXHN_H168N_V3.5.bin resources/ZXHN_H168N_V3.5.xml2
python3 examples/encode.py --signature "ZXHN H168N V3.5" --use-signature-encryption resources/ZXHN_H168N_V3.5.xml resources/ZXHN_H168N_V3.5.bin2

python3 examples/decode.py resources/ZXHN_H298Q_C7_config.bin resources/ZXHN_H298Q_C7_config.xml2
python3 examples/encode.py --signature "ZXHN H298Q V7.0" --use-signature-encryption resources/ZXHN_H298Q_C7_config.xml resources/ZXHN_H298Q_C7_config.bin2

python3 examples/decode.py resources/ZXHN_H267A.bin resources/ZXHN_H267A.xml2
python3 examples/encode.py --signature "ZXHN H267A V1.0" resources/ZXHN_H267A.xml resources/ZXHN_H267A.bin2

python3 examples/decode.py resources/ZXHN_H298N.bin resources/ZXHN_H298N.xml2
python3 examples/encode.py --signature "ZXHN H298N" resources/ZXHN_H298N.xml resources/ZXHN_H298N.bin2

python3 examples/decode.py resources/ZXV10_H201L_V2.0.bin resources/ZXV10_H201L_V2.0.xml2
python3 examples/encode.py --signature "ZXV10 H201L V2.0" resources/ZXV10_H201L_V2.0.xml resources/ZXV10_H201L_V2.0.bin2
