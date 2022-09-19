# Enigma Template Code for CNU Information Security 2022
# Resources from https://www.cryptomuseum.com/crypto/enigma

# This Enigma code implements Enigma I, which is utilized by
# Wehrmacht and Luftwaffe, Nazi Germany.
# This version of Enigma does not contain wheel settings, skipped for
# adjusting difficulty of the assignment.

from copy import deepcopy
from ctypes import ArgumentError

# Enigma Components
ETW = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#     "BDFHJLCPRTXVZNYEIWGAKMUSQO"
#     "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
#     "AJDKSIRUXBLHWTMCQGZNPYFVOE"

WHEELS = {
    "I": {
        "wire": "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        "turn": 16
    },
    "II": {
        "wire": "AJDKSIRUXBLHWTMCQGZNPYFVOE",
        "turn": 4
    },
    "III": {
        "wire": "BDFHJLCPRTXVZNYEIWGAKMUSQO",
        "turn": 21
    }
}

UKW = {
    "A": "EJMZALYXVBWFCRQUONTSPIKHGD",
    "B": "YRUHQSLDPXNGOKMIEBFZCWVJAT",
    "C": "FVPJIAOYEDRZXWGCTKUQSBNMHL"
}

# Enigma Settings
SETTINGS = {
    "UKW": None,
    "WHEELS": [],
    "WHEEL_POS": [],
    "ETW": ETW,
    "PLUGBOARD": []
}


def apply_settings(ukw, wheel, wheel_pos, plugboard):
    if not ukw in UKW:
        raise ArgumentError(f"UKW {ukw} does not exist!")
    SETTINGS["UKW"] = UKW[ukw]

    wheels = wheel.split(' ')
    for wh in wheels:
        if not wh in WHEELS:
            raise ArgumentError(f"WHEEL {wh} does not exist!")
        SETTINGS["WHEELS"].append(WHEELS[wh])

    wheel_poses = wheel_pos.split(' ')
    for wp in wheel_poses:
        if not wp in ETW:
            raise ArgumentError(f"WHEEL position must be in A-Z!")
        SETTINGS["WHEEL_POS"].append(ord(wp) - ord('A'))

    plugboard_setup = plugboard.split(' ')
    for ps in plugboard_setup:
        if not len(ps) == 2 or not ps.isupper():
            raise ArgumentError(f"Each plugboard setting must be sized in 2 and caplitalized; {ps} is invalid")
        SETTINGS["PLUGBOARD"].append(ps)


# Enigma Logics Start

# Plugboard
def pass_plugboard(input):
    for plug in SETTINGS["PLUGBOARD"]:
        if str.startswith(plug, input):
            return plug[1]
        elif str.endswith(plug, input):
            return plug[0]

    return input


# ETW
def pass_etw(input):
    return SETTINGS["ETW"][ord(input) - ord('A')]


# Wheels
def pass_wheels(input, reverse=False):
    # Implement Wheel Logics
    # Keep in mind that reflected signals pass wheels in reverse order
    if reverse:
        temp = (ord(input) - ord('A') + SETTINGS["WHEEL_POS"][0]) % 26
        temp = chr(temp + ord('A'))
        cnt = 0
        for ch in SETTINGS["WHEELS"][0]["wire"]:
            if ch == temp:
                break
            cnt += 1
        input = SETTINGS["ETW"][cnt]

        temp = (ord(input)-ord('A') +SETTINGS["WHEEL_POS"][1] -SETTINGS["WHEEL_POS"][0]) % 26
        temp = chr(temp + ord('A'))
        cnt = 0
        for ch in SETTINGS["WHEELS"][1]["wire"]:
            if ch == temp:
                break
            cnt += 1
        input = SETTINGS["ETW"][cnt]

        temp = (ord(input) - ord('A') + SETTINGS["WHEEL_POS"][2] - SETTINGS["WHEEL_POS"][1]) % 26
        temp = chr(temp + ord('A'))
        cnt = 0
        for ch in SETTINGS["WHEELS"][2]["wire"]:
            if ch == temp:
                break
            cnt += 1
        input = SETTINGS["ETW"][cnt]

        temp = (26 + ord(input) - ord('A') - SETTINGS["WHEEL_POS"][2]) % 26
        input = SETTINGS["ETW"][temp]

    else:
        temp = (ord(input) - ord('A') + SETTINGS["WHEEL_POS"][2]) % 26
        input = SETTINGS["WHEELS"][2]["wire"][temp]

        temp = (ord(input) - ord('A') + SETTINGS["WHEEL_POS"][1] - SETTINGS["WHEEL_POS"][2]) % 26
        input = SETTINGS["WHEELS"][1]["wire"][temp]

        temp = (ord(input) - ord('A') + SETTINGS["WHEEL_POS"][0] - SETTINGS["WHEEL_POS"][1]) % 26
        input = SETTINGS["WHEELS"][0]["wire"][temp]

        temp = (26 + ord(input) - ord('A') - SETTINGS["WHEEL_POS"][0]) % 26
        input = SETTINGS["ETW"][temp]

    return input


# UKW
def pass_ukw(input):
    return SETTINGS["UKW"][ord(input) - ord('A')]


# Wheel Rotation
def rotate_wheels():
    # Implement Wheel Rotation Logics
    SETTINGS["WHEEL_POS"][2] += 1
    SETTINGS["WHEEL_POS"][2] = SETTINGS["WHEEL_POS"][2] % 26
    if SETTINGS["WHEEL_POS"][2] == SETTINGS["WHEELS"][2]["turn"] + 1:
        SETTINGS["WHEEL_POS"][1] += 1
        SETTINGS["WHEEL_POS"][1] = SETTINGS["WHEEL_POS"][1] % 26
    if SETTINGS["WHEEL_POS"][1] == SETTINGS["WHEELS"][1]["turn"] + 1:
        SETTINGS["WHEEL_POS"][0] += 1
        SETTINGS["WHEEL_POS"][0] = SETTINGS["WHEEL_POS"][0] % 26
    pass


# Enigma Exec Start
plaintext = input("Plaintext to Encode: ")
plaintext = plaintext.upper()
ukw_select = input("Set Reflector (A, B, C): ")
wheel_select = input("Set Wheel Sequence L->R (I, II, III): ")
wheel_pos_select = input("Set Wheel Position L->R (A~Z): ")
plugboard_setup = input("Plugboard Setup: ")

apply_settings(ukw_select, wheel_select, wheel_pos_select, plugboard_setup)

for ch in plaintext:
    rotate_wheels()

    encoded_ch = ch

    encoded_ch = pass_plugboard(encoded_ch)
    encoded_ch = pass_etw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch)
    encoded_ch = pass_ukw(encoded_ch)
    encoded_ch = pass_wheels(encoded_ch, reverse=True)
    encoded_ch = pass_plugboard(encoded_ch)

    print(encoded_ch, end='')

    # 예시
    # swdgfuscydswfmyigoft
    # lunchtodayissandwich
    # UKW C, Rotor III-I-II (Y-B-B), Ring 1-1-1, A-V / F-T
    # C
    # III I I
    # Y B B
    # AV FT
    # ord('a') -> 97return