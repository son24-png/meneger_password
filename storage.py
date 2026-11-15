import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from pathlib import Path
import secrets
import base64

magic_b = 0x504D5631  #записывается в начало файла чтобы отличить от ненужных нам
version_b = 1

vault_path = Path('data/vault.bin')

fields = ("site", "login", "password")

def generate_key() -> str:
    key = secrets.token_bytes(32)
    key_text = base64.urlsafe_b64encode(key).decode("ascii")
    return key_text

def decode_key(key_text: str) -> bytes:
    if not isinstance(key_text, str):
        raise ValueError("Ключ должен быть строкой")

    try:
        key = base64.b64decode(
            key_text,
            altchars=b"-_",
            validate=True
        )
    except (ValueError, base64.binascii.Error):
        raise ValueError("Некорректный формат ключа")

    if len(key) != 32:
        raise ValueError("Ключ должен содержать 256 бит")

    return key

def serialize_entries(entries: list[dict[str, str]]) -> bytes:
    out = bytearray()
    # Заголовок файла
    out += struct.pack(">IHI", magic_b, version_b, len(entries))

    for entry in entries:
        if not isinstance(entry, dict) or set(entry.keys()) != set(fields):
            raise ValueError("Некорректная структура записи")
        for field in fields:
            value = entry[field]

            if not isinstance(value, str):
                raise ValueError(f"Поле {field} должно быть строкой")

            value_b = value.encode("utf-8")

            if len(value_b) > 65535:
                raise ValueError(f"Поле {field} слишком длинное")

            # Записываем длину поля и само значение
            out += struct.pack(">H", len(value_b))
            out += value_b

    return bytes(out)


def deserialize_entries(data: bytes) -> list[dict[str, str]]:
    if len(data) < 10:
        raise ValueError("Файл слишком короткий")

    magic, version, count = struct.unpack(">IHI", data[:10])

    if magic != magic_b:
        raise ValueError("Неверный формат файла")

    if version != version_b:
        raise ValueError("Неподдерживаемая версия")

    offset = 10
    entries = []

    if count > (len(data) - 10) // 6:
        raise ValueError("Некорректное количество записей")

    for _ in range(count):
        entry = {}

        for field in fields:
            if offset + 2 > len(data):
                raise ValueError("Файл обрезан")

            (field_len,) = struct.unpack(
                ">H", data[offset:offset + 2]
            )
            offset += 2

            if offset + field_len > len(data):
                raise ValueError("Файл обрезан")

            value_b = data[offset:offset + field_len]
            offset += field_len

            try:
                value = value_b.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("Некорректные текстовые данные")

            entry[field] = value

        entries.append(entry)

    if offset != len(data):
        raise ValueError("В файле обнаружены лишние данные")

    return entries




def save_vault(entries: list[dict[str, str]], key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Ключ должен содержать 32 байта")

    # Преобразуем записи в бинарные данные
    raw = serialize_entries(entries)

    # Создаём новый случайный nonce
    nonce = secrets.token_bytes(12)

    # Шифруем данные
    aes = AESGCM(key)
    encrypted_data = aes.encrypt(nonce, raw, None)

    # Объединяем nonce и зашифрованные данные
    file_data = nonce + encrypted_data

    # Создаём папку, если её ещё нет
    vault_path.parent.mkdir(parents=True, exist_ok=True)

    # Сначала записываем временный файл
    temp_path = vault_path.with_suffix(".tmp")
    temp_path.write_bytes(file_data)

    # Заменяем старую версию новой
    temp_path.replace(vault_path)


def load_vault(key: bytes) -> list[dict[str, str]]:
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Ключ должен содержать 32 байта")

    if not vault_path.exists():
        return []

    file_data = vault_path.read_bytes()

    # Минимум 12 байт nonce и 16 байт тега аутентификации
    if len(file_data) < 28:
        raise ValueError("Файл хранилища повреждён")

    nonce = file_data[:12]
    encrypted_data = file_data[12:]

    try:
        aes = AESGCM(key)
        raw = aes.decrypt(nonce, encrypted_data, None)
    except InvalidTag:
        raise RuntimeError(
            "Не удалось открыть хранилище: неверный ключ "
            "или данные повреждены"
        )

    return deserialize_entries(raw)


def upsert_entry(entries: list[dict[str, str]], site: str, login: str, password: str) -> list[dict[str, str]]:
    result = [entry.copy() for entry in entries]

    for i, entry in enumerate(result):
        if entry["site"] == site and entry["login"] == login:
            result[i] = {
                "site": site,
                "login": login,
                "password": password
            }
            return result

    result.append({
        "site": site,
        "login": login,
        "password": password
    })

    return result


def delete_entry(entries: list[dict[str, str]], site: str, login: str) -> list[dict[str, str]]:
    return [
        entry.copy()
        for entry in entries
        if not (entry["site"] == site and entry["login"] == login)
    ]
