import secrets
import string


def generate_password(length: int = 16, use_lowercase: bool = True, use_uppercase: bool = True, use_digits: bool = True, use_symbols: bool = True) -> str:
#length - длина, use_lowercase - использовать строчные буквы, use_uppercase - использовать заглавные, use_digits - испл цифры, use_symbols - испл символы

    if not isinstance(length, int) or isinstance(length, bool) or not 16 <= length <= 64:
        raise ValueError("Длина пароля должна быть целым числом от 16 до 64")

    groups = []

    if use_lowercase:                                   
        groups.append(string.ascii_lowercase)

    if use_uppercase:
        groups.append(string.ascii_uppercase)

    if use_digits:
        groups.append(string.digits)

    if use_symbols:
        groups.append(string.punctuation)

    if not groups:
        raise ValueError("Выберите хотя бы одну категорию символов")

    alphabet = "".join(groups)

    # Гарантируем присутствие символа каждой категории !!!
    password = [secrets.choice(group) for group in groups]

    # Заполняем оставшиеся позиции
    for _ in range(length - len(password)):
        password.append(secrets.choice(alphabet))

    # Криптографически стойкое перемешивание !!!
    secrets.SystemRandom().shuffle(password)

    return "".join(password)
