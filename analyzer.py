import math
import secrets
import string
from zxcvbn import zxcvbn
from typing import Literal 

#10k-most-common.txt
def load_blocklist(path='10k-most-common.txt') -> set:
    with open(path, encoding='utf-8', errors='ignore') as f:
        return {line.strip().lower() for line in f}

BLOCKLIST = load_blocklist()

SPEEDS = {
    "online": 100,
    "offline_weak_hash": 1e11,
    "offline_bcrypt": 1e5,
    "offline_argon2": 1e3,
    "quantum": 1e15,
}

def crack_time_seconds(bits: float, mode: str = "offline_bcrypt") -> float: #время взлома
    return (2 ** bits) / (2 * SPEEDS[mode])

def humanize_time(seconds: float) -> str:  #человекочитаемое время
    
    if seconds < 1:
        return "мгновенно"
    if seconds < 60:
        return f"{seconds:.1f} секунд"
    if seconds < 3600:
        return f"{seconds / 60:.1f} минут"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} часов"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.1f} дней"
    years = seconds / 31_536_000
    if years < 1000:
        return f"{years:.1f} лет"
    if years < 1_000_000:
        return f"{years / 1000:.1f} тысяч лет"
    return f"{years / 1_000_000:.1f} миллионов лет"


NIST_THRESHOLD_BITS = 80  #порог битов энтропии

def strength_percent(bits: float) -> float:  #процент надежности для сони
    return min(100.0, bits / NIST_THRESHOLD_BITS * 100)



def nist_compliance_report(password: str) -> dict:
    length = len(password)
    alphabet_size = 0
    if any(c.islower() for c in password): alphabet_size += 26
    if any(c.isupper() for c in password): alphabet_size += 26
    if any(c.isdigit() for c in password): alphabet_size += 10
    if any(c in string.punctuation for c in password): alphabet_size += 32
    entropy_bits = len(password) * math.log2(alphabet_size) if alphabet_size > 1 else 0
    entropy_percent = min(entropy_bits / 100 * 100, 100.0)
    result = zxcvbn(password)
    zxcvbn_score = result['score']
    crack_time = result['crack_times_display']['offline_slow_hashing_1e4_per_second']
    effective_entropy = min(entropy_bits, result['guesses_log10'] * 3.32)
    zxcvbn_crack_time = humanize_time(crack_time_seconds(effective_entropy, "offline_bcrypt"))
    is_blocklisted = password.lower() in BLOCKLIST
    reasons = []
    if not(16 < length < 64):
        reasons.append(f'длина {length} < 15')
    if is_blocklisted:
        reasons.append('пароль найден в списке утечек')
    if entropy_bits < 60:
        reasons.append(f'энтропия {entropy_bits:.1f} бит < 60')

    valid = len(reasons) == 0
    if valid:
        return {
        'verdict': 'Соответствует NIST Rev. 4',
        'details': {
            'length': len(password),
            'entropy_bits': entropy_bits,
            'entropy_percent': entropy_percent,
            'zxcvbn_crack_time': zxcvbn_crack_time,
            'is_blocklisted': is_blocklisted}
        }
    else:
        return {
        'valid': False,
        'verdict': f'Не соответствует: {", ".join(reasons)}',
        'details': {
            'length': len(password),
            'entropy_bits': entropy_bits,
            'entropy_percent': entropy_percent,
            'zxcvbn_crack_time': zxcvbn_crack_time,
            'is_blocklisted': is_blocklisted},
        'suggestion': 'Сгенерируйте новый пароль'
        }
