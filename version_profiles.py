"""Version-specific RVAs recovered from static signatures and live objects."""
PROFILES = {
    'v248': {'label': 'V2.4.8', 'historical_base': 0xc20000},
    'v253': {'label': 'V2.5.3', 'rvas': {
        0x11bac74: 0x5a5e50,  # TFormRegist VMT
        0xd97b24: 0x177cfc,   # registration message dispatcher
        0x11dd744: 0x5c8920,  # main global
        0x11dd79c: 0x5c8978,  # TFormConnectAdd
        0x11dd7dc: 0x5c89b8,  # TFormConnectSet
        0x11de3dc: 0x5c95b8,  # login global
        0x11de424: 0x5c9600,  # registration global
        0x11e55d8: 0x5d07b4,  # application global
        0x1119a00: 0x4f9140,  # TForm1 VMT
        0xce5d04: 0xc0944,    # radius multiply by two
        0xce696d: 0xc15dd,    # scan denominator sequence
        0xce6438: 0xc10a8,    # parallel recognizer float 100.0
        0xdaeadc: 0x18ecbc,   # native FastMM allocation entry
        0x1732d49: 0x748c1b,  # exact EIP after observed main-pointer write
    }},
}


def relocate(base, historical_address, profile_id):
    profile = PROFILES[profile_id]
    if 'rvas' in profile:
        if historical_address not in profile['rvas']:
            raise ValueError('此辅助地址尚未迁移到 ' + profile['label'] + ': ' + hex(historical_address))
        return base + profile['rvas'][historical_address]
    return base + historical_address - profile['historical_base']
