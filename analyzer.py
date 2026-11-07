from zxcvbn import zxcvbn
from pathlib import Path

#10k-most-common.txt
def load_blocklist(path=None):
    if path is None:
        path = Path(__file__).resolve().parent / "10k-most-common.txt"

    if not path.exists():
        return None

    with open(path, encoding="utf-8") as file:
        return {
            line.strip().lower()
            for line in file
            if line.strip()
        }

BLOCKLIST = load_blocklist()

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

def analyze_password(password: str) -> dict:
        if not isinstance(password, str):
            raise TypeError('Пароль должен быть строкой')
        if not password:
            raise ValueError('Введите пароль')
        result = zxcvbn(password)
        zxcvbn_score = result['score']
        crack_time = result['crack_times_seconds']['offline_slow_hashing_1e4_per_second']
        crack_time_display = humanize_time(crack_time)
        reasons = []
        length = len(password)
        if length < 16:
            reasons.append(f'длина {length} < 16')
        elif length > 64:
            reasons.append(f'длина {length} > 64')
        
        if BLOCKLIST is None:
            is_blocklisted = None
        else:
            is_blocklisted = password.lower() in BLOCKLIST
            if is_blocklisted:
                reasons.append("Найден в BLOCKLIST")

        if zxcvbn_score == 0:
            verdict = 'Очень слабый'
            percent = 0
        elif zxcvbn_score == 1:
            verdict = 'Слабый'
            percent = 25
        elif zxcvbn_score == 2:
            verdict = 'Средний'
            percent = 50
        elif zxcvbn_score == 3:
            verdict = 'Сильный'
            percent = 75
        elif zxcvbn_score == 4:
            verdict = 'Очень сильный'
            percent = 100

        valid = len(reasons) == 0
        return {
            'valid': valid,
            'verdict': verdict,
            'details': {
                'length': len(password),
                'percent': percent,
                'crack_time': crack_time_display,
                'is_blocklisted': is_blocklisted
                },
            'reasons': reasons
            }
