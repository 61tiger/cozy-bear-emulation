# poshspy/server/dga.py
# POSHSPY Domain Generation Algorithm — Python reimplementation
# Source: matthewdunwoody/POSHSPY.ps1
# Functions: getDateParam, generateRndHostName, generateFhHostName,
#            generatePathName, generateWorkUrl, getIndexUrl

import random
import math
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────────────
# DGA parameters — must match POSHSPY.ps1 exactly
# Source: $rdict, $cdict, $ratio, $period, $mseed
# ─────────────────────────────────────────────────────────────────────────────

# $rdict — random hostname dict
# format: (word_list, is_required, postfix_digit_len)
RDICT = [
    (['www'],                                                           1, 0),
    (['*redacted*'],                                                    1, 0),
    (['org'],                                                           1, 0),
]

# $cdict — path component dict
# format: (word_list, separator(1=/,0=.), is_required, postfix_digit_len)
CDICT = [
    (['variant','excretions','accumulators','winslow','whistleable',
      'len','undergraduate','colleges','pies','nervous'],              1, 1, 0),
    (['postscripts','miniatures','comprehensibility',
      'arranger','sulphur'],                                           2, 1, 0),
    (['php'],                                                          3, 1, 0),
]

RATIO  = 100   # $ratio  — 100 = always use rdict, never fdict
PERIOD = 0     # $period — 0 = weekly
MSEED  = 834777  # $mseed


# ─────────────────────────────────────────────────────────────────────────────
# PowerShell Get-Random reimplementation
# PS Get-Random -SetSeed uses System.Random which is a linear congruential
# generator: next = (seed * 0x343FD + 0x269EC3) & 0x7FFFFFFF >> 16 & 0x7FFF
# Source: .NET System.Random reference implementation
# ─────────────────────────────────────────────────────────────────────────────

class PSRandom:
    """
    Reimplements .NET System.Random used by PowerShell Get-Random.
    Source: coreclr/src/libraries/System.Private.CoreLib/src/System/Random.cs
    """
    MBIG = 0x7fffffff
    MSEED_CONST = 161803398

    def __init__(self, seed: int):
        self._seed_array = [0] * 56
        self._inext = 0
        self._inextp = 21
        self._init(seed)

    def _init(self, seed: int):
        sa = self._seed_array
        ii = 0
        mj = self.MSEED_CONST - abs(seed)
        mj &= self.MBIG
        sa[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = (21 * i) % 55
            sa[ii] = mk
            mk = mj - mk
            if mk < 0:
                mk += self.MBIG
            mj = sa[ii]
        for _ in range(5):
            for i in range(1, 56):
                sa[i] -= sa[1 + (i + 30) % 55]
                if sa[i] < 0:
                    sa[i] += self.MBIG

    def _internal_sample(self) -> int:
        inext  = self._inext
        inextp = self._inextp
        inext  = inext  + 1 if inext  < 55 else 1
        inextp = inextp + 1 if inextp < 55 else 1
        retval = self._seed_array[inext] - self._seed_array[inextp]
        if retval == self.MBIG:
            retval -= 1
        if retval < 0:
            retval += self.MBIG
        self._seed_array[inext] = retval
        self._inext  = inext
        self._inextp = inextp
        return retval

    def next(self, max_val: int = None) -> int:
        """Get-Random equivalent — returns [0, max_val)"""
        if max_val is None:
            return self._internal_sample()
        return int(self._internal_sample() * (max_val / self.MBIG))


# ─────────────────────────────────────────────────────────────────────────────
# DGA functions — direct Python translation of PS1
# ─────────────────────────────────────────────────────────────────────────────

def get_date_param(date: datetime, period: int, magic_seed: int) -> int:
    """
    Source: getDateParam()
    $dateparam = $yearnumber * 17 + $monthnumber * 13 + $weeknumber * 19 + $magicseed
    """
    year  = date.year
    month = date.month
    week  = 0
    if period == 0:
        day  = date.day
        week = math.floor((day - 1) / 7 + 1)
    return year * 17 + month * 13 + week * 19 + magic_seed


def generate_rnd_hostname(dateparam: int, rdict: list) -> str:
    """
    Source: generateRndHostName()
    Get-Random -SetSeed ($dateparam + 131)
    """
    rng = PSRandom(dateparam + 131)
    res = ''
    for part in rdict:
        word_list, is_required, postfix_len = part
        is_included = is_required or (rng.next(2) % 2)
        if not is_included:
            continue
        res += word_list[rng.next(len(word_list))]
        if postfix_len != 0 and rng.next(2) % 2 != 0:
            res += str(rng.next(int(math.pow(10, postfix_len))))
        res += '.'
    return res.rstrip('.')


def generate_fh_hostname(dateparam: int, fdict: list) -> str:
    """
    Source: generateFhHostName()
    Get-Random -SetSeed ($dateparam + 319)
    """
    if not fdict:
        return ''
    rng = PSRandom(dateparam + 319)
    res = ''
    fixed_part = fdict[0][rng.next(len(fdict[0]))]
    preface  = fixed_part[0]
    postface = fixed_part[1]
    res += preface
    if res:
        res += '.'
    user_part_list, postfix_len = fdict[1][0], fdict[1][1]
    res += user_part_list[rng.next(len(user_part_list))]
    if postfix_len != 0 and rng.next(2) % 2 != 0:
        res += str(rng.next(int(math.pow(10, postfix_len))))
    if postface:
        res += '.'
    res += postface
    return res


def generate_path_name(dateparam: int, cdict: list) -> str:
    """
    Source: generatePathName()
    Get-Random -SetSeed ($dateparam + 473)
    separator: dict[i][1] == 1 -> '/', else '.'
    """
    rng = PSRandom(dateparam + 473)
    res = ''
    for part in cdict:
        word_list, sep_type, is_required, postfix_len = part
        is_included = is_required or (rng.next(2) % 2)
        if not is_included:
            continue
        res += word_list[rng.next(len(word_list))]
        if postfix_len != 0 and rng.next(2) % 2 != 0:
            res += str(rng.next(int(math.pow(10, postfix_len))))
        res += '/' if sep_type == 1 else '.'
    return res.rstrip('.')


def generate_work_url(dateparam: int, rdict: list, fdict: list,
                      cdict: list, ratio: int) -> str | None:
    """
    Source: generateWorkUrl()
    Get-Random -SetSeed ($dateparam + 731)
    ratio=100 -> always rdict, never fdict
    """
    if not cdict or (not fdict and not rdict):
        return None
    rng = PSRandom(dateparam + 731)
    res = ''
    if rng.next(100) >= ratio:
        res += generate_fh_hostname(dateparam, fdict)
    else:
        res += generate_rnd_hostname(dateparam, rdict)
    return res + '/' + generate_path_name(dateparam, cdict)


def get_index_url(url: str) -> str | None:
    """
    Source: getIndexUrl()
    Strips path, optionally appends /index.html or /index.php
    """
    if not url:
        return None
    idx = url.find('/')
    ret = url if idx == -1 else url[:idx]
    if random.randint(0, 1) == 0:
        ext = random.choice(['html', 'php'])
        ret += f'/index.{ext}'
    return ret


def get_current_url(date: datetime = None,
                    period: int = PERIOD,
                    mseed: int = MSEED,
                    rdict: list = RDICT,
                    fdict: list = None,
                    cdict: list = CDICT,
                    ratio: int = RATIO) -> str | None:
    """
    Generate the C2 URL for a given date — matches what POSHSPY.ps1 will beacon to.
    Call with no args to get today's URL.
    """
    if date is None:
        date = datetime.utcnow()
    if fdict is None:
        fdict = []
    dateparam = get_date_param(date, period, mseed)
    url = generate_work_url(dateparam, rdict, fdict, cdict, ratio)
    return f'http://{url}' if url else None


if __name__ == '__main__':
    # print this week's C2 URL
    url = get_current_url()
    print(f'[*] Current C2 URL : {url}')
    print(f'[*] Decoy index URL: http://{get_index_url(url.replace("http://", ""))}')