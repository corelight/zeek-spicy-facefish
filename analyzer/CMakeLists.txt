spicy_add_analyzer(
    NAME FACEFISH
    PACKAGE_NAME FACEFISH
    SOURCES analyzer.spicy analyzer.evt zeek_analyzer.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
