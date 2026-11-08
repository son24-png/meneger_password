from zxcvbn import zxcvbn
from pathlib import Path
from itertools import combinations
import math

def calculate_search_space(length: int, generator_settings: dict):
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValueError("Длина пароля должна быть положительным целым числом")

    if not isinstance(generator_settings, dict):
        raise ValueError("Настройки должны быть словарём")
    
    required_keys = [
    "use_lowercase",
    "use_uppercase",
    "use_digits",
    "use_symbols"
    ]

    for key in required_keys:
        if key not in generator_settings:
            raise ValueError(f"Отсутствует настройка: {key}")

        if not isinstance(generator_settings[key], bool):
            raise ValueError(f"Настройка {key} должна иметь значение True или False")
    
    groups = []

    if generator_settings["use_lowercase"]:
        groups.append(26)

    if generator_settings["use_uppercase"]:
        groups.append(26)

    if generator_settings["use_digits"]:
        groups.append(10)

    if generator_settings["use_symbols"]:
        groups.append(32)
    
    if not groups:
        raise ValueError("Выберите хотя бы одну категорию символов")

    N = sum(groups)
    total = N ** length 

    for r in range(1, len(groups) + 1):
        for subset in combinations(groups, r):
            remaining = N - sum(subset)

            if r % 2 == 1:
                total -= remaining ** length
            else:
                total += remaining ** length

    return total

def calculate_search_space_bits(length: int, generator_settings: dict) -> float:
    search_space = calculate_search_space(length, generator_settings)
    return math.log2(search_space)


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

def analyze_password(password: str, generator_settings: dict |None=None) -> dict:
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

    if generator_settings is not None:
        search_space = calculate_search_space(len(password), generator_settings)
        search_space_bits = math.log2(search_space)
    else:
        search_space = None
        search_space_bits = None

    valid = len(reasons) == 0
    return {
        'valid': valid,
        'verdict': verdict,
        'details': {
        'length': len(password),
        'percent': percent,
        'crack_time': crack_time_display,
        'is_blocklisted': is_blocklisted,
        'search_space': search_space,  #кол-во вариантов
        'search_space_bits': search_space_bits #кол-во вариантов в битах "Размер пространства поиска (бит)"
            },
        'reasons': reasons
        }
