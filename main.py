from core.generator import generate_password
from core.analyzer import analyze_password


# Настройки генерации
settings = {
    "use_lowercase": True,
    "use_uppercase": True,
    "use_digits": True,
    "use_symbols": False
}


def generate_and_analyze(length: int, settings: dict) -> dict: 
    password = generate_password(length=length,**settings)

    analysis = analyze_password(password, generator_settings=settings)

    return {'password': password, 'analysis': analysis}

def analyze_personal_password(password: str) -> dict:
    return analyze_password(password)

if __name__ == "__main__":
    settings = {
        "use_lowercase": True,
        "use_uppercase": True,
        "use_digits": True,
        "use_symbols": False
    }

    result = generate_and_analyze(20, settings)

    print("Пароль сгенерирован")
    print("Результат анализа:", result["analysis"])