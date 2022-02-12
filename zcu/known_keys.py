"""Known encryption keys for ZTE router config.bin files"""

# 1st element is the key, everything else is the start of the signature
KNOWN_KEYS = {
    "MIK@0STzKpB%qJZe": ["zxhn h118n e"],
    "MIK@0STzKpB%qJZf": ["zxhn h118n v"],
    "402c38de39bed665": ["zxhn h168n v3", "zxhn h267a"],
    "Q#Zxn*x3kVLc":     ["zxhn h168n v2"],
    # due to bug, orig. is "Wj%2$CjM"
    "Wj":               ["zxhn h298n"],
    "m8@96&ZG3Nm7N&Iz": ["zxhn h298a"],
    "GrWM2Hz&LTvz&f^5": ["zxhn h108n"],
    "GrWM3Hz&LTvz&f^9": ["zxhn h168n h"],
    "Renjx%2$CjM":      ["zxhn h208n", "zxhn h201l"],
    "tHG@Ti&GVh@ql3XN": ["zxhn h267n"],
    # not sure, might be related to H108N
    "SDEwOE5WMi41Uk9T": ["TODO"]
}


def find_key(signature):
    signature = signature.lower()
    for key, sigs in KNOWN_KEYS.items():
        for sig in sigs:
            if signature.startswith(sig):
                return key.encode().ljust(16, b"\0")[:16]
    return None


def get_all_keys():
    return list(map(lambda x: x.encode().ljust(16, b"\0")[:16], KNOWN_KEYS.keys()))
