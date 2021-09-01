"""Known encryption keys for ZTE router config.bin files"""
KNOWN_KEYS = [  # 1st element is the key, the rest are the beginnings of the signatures in lower-case
    ["MIK@0STzKpB%qJZe",    "zxhn h118n e"],
    ["MIK@0STzKpB%qJZf",    "zxhn h118n v"],
    ["402c38de39bed665",    "zxhn h168n v",     "zxhn h267a"],
    ["Wj",                  "zxhn h298n"],                          # due to bug, orig. is 'Wj%2$CjM'
    ["m8@96&ZG3Nm7N&Iz",    "zxhn h298a"],
    ["GrWM2Hz&LTvz&f^5",    "zxhn h108n"],
    ["GrWM3Hz&LTvz&f^9",    "zxhn h168n h"],
    ["Renjx%2$CjM",         "zxhn h208n",       "zxhn h201l"],
    ["tHG@Ti&GVh@ql3XN",    "zxhn h267n"]
]

def find_key(signature):
    signature = signature.lower()
    for key_info in KNOWN_KEYS:
        for sig in key_info[1:]:
            if signature.startswith(sig):
                return key_info[0].encode().ljust(16, b'\0')[:16]
    return None
