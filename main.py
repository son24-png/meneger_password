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



#storage

def validate_entry(site: str, login: str, password: str) -> None:
    values = {
        "site": site,
        "login": login,
        "password": password
    }

    for field, value in values.items():
        if not isinstance(value, str):
            raise ValueError(f"{field} должен быть строкой")

        if not value.strip():
            raise ValueError(f"{field} не может быть пустым")

        if len(value.encode("utf-8")) > 65535:
            raise ValueError(f"{field} слишком длинный")

class VaultSession:

    def __init__(self, key: bytes, entries: list[dict[str, str]]): #Сохраняет ключ и записи внутри объекта сессии
        self._key = key
        self._entries = entries

    @classmethod                                   #Создаёт сессию: проверяет ключ, расшифровывает хранилище и загружает записи
    def open(cls, key_text: str):
        key = vault_storage.decode_key(key_text)
        entries = vault_storage.load_vault(key)

        return cls(key, entries)

    @property
    def is_open(self) -> bool:         #Позволяет проверить состояние
        return self._key is not None

    def _check_open(self):
        if not self.is_open:
            raise RuntimeError("Хранилище закрыто")

    def get_entries(self) -> list[dict[str, str]]:          #Возвращает копию списка
        self._check_open()
        return [entry.copy() for entry in self._entries]

    def add_entry(self, site: str, login: str, password: str) -> None:  #добавляет новую запись или обновляет существующую, затем сохраняет изменения
        self._check_open()
        validate_entry(site, login, password)

        updated_entries = vault_storage.upsert_entry(
            self._entries, site, login, password
        )

        vault_storage.save_vault(updated_entries, self._key)
        self._entries = updated_entries


    def remove_entry(self, site: str, login: str) -> None:     #удаляет запись и сохраняет изменения
        self._check_open()

        updated_entries = vault_storage.delete_entry(
            self._entries, site, login
        )

        vault_storage.save_vault(updated_entries, self._key)
        self._entries = updated_entries


    def save(self) -> None:                        #сохраняет текущее содержимое сессии
        self._check_open()
        vault_storage.save_vault(self._entries, self._key)

    def close(self) -> None:
        self._entries.clear()
        self._key = None

def create_vault_key() -> str:    #Создаёт новый ключ для хранилища
    return vault_storage.generate_key()


def open_vault(key_text: str) -> list[dict[str, str]]:  #Открывает хранилище по введённому ключу
    key = vault_storage.decode_key(key_text)
    return vault_storage.load_vault(key)


def save_entries(entries: list[dict[str, str]], key_text: str) -> None:  #Сохраняет весь список записей
    for entry in entries:
        if not isinstance(entry, dict) or set(entry.keys()) != set(vault_storage.fields):
            raise ValueError("Некорректная структура записи")

        validate_entry(
            entry["site"],
            entry["login"],
            entry["password"]
        )
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
    validate_entry(site, login, password)
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
