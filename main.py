from core.generator import generate_password
from core.analyzer import analyze_password
from core import storage as vault_storage


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

#storage

def create_vault_key() -> str:    #Создаёт новый ключ для хранилища
    return vault_storage.generate_key()


def open_vault(key_text: str) -> list[dict[str, str]]:  #Открывает хранилище по введённому ключу
    key = vault_storage.decode_key(key_text)
    return vault_storage.load_vault(key)


def save_entries(entries: list[dict[str, str]], key_text: str) -> None:  #Сохраняет весь список записей
    key = vault_storage.decode_key(key_text)
    vault_storage.save_vault(entries, key)

#Добавляет или обновляет запись и сохраняет результат
def add_entry(
    entries: list[dict[str, str]],
    site: str,
    login: str,
    password: str,
    key_text: str
) -> list[dict[str, str]]:
    key = vault_storage.decode_key(key_text)

    updated_entries = vault_storage.upsert_entry(
        entries, site, login, password
    )

    vault_storage.save_vault(updated_entries, key)

    return updated_entries

#Удаляет запись и сохраняет результат
def remove_entry(
    entries: list[dict[str, str]],
    site: str,
    login: str,
    key_text: str
) -> list[dict[str, str]]:
    key = vault_storage.decode_key(key_text)

    updated_entries = vault_storage.delete_entry(
        entries, site, login
    )

    vault_storage.save_vault(updated_entries, key)

    return updated_entries
