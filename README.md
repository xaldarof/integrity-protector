# Integrity Protector: Модуль защиты целостности скриптов
```Ходаров Темур 10/05/2025```
[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Integrity Protector** - это простой модуль на Python, предназначенный для защиты целостности скриптов с использованием символьного пароля. Он использует алгоритм HMAC-SHA256 для создания криптографической контрольной суммы (MAC-тега) на основе содержимого скрипта и предоставленного пароля. При последующей верификации модуль проверяет, не был ли скрипт изменен с момента защиты, путем повторного вычисления контрольной суммы и ее сравнения с сохраненной.

## Основные возможности

* **Защита скрипта:** Генерация защищенного представления скрипта, включающего контрольную сумму (HMAC-SHA256), случайную соль и исходное содержимое скрипта.
* **Сохранение защищенной информации:** Сохранение защищенных данных в файл в формате JSON.
* **Загрузка защищенной информации:** Загрузка защищенных данных из файла JSON.
* **Верификация целостности:** Проверка целостности скрипта путем сравнения повторно вычисленной контрольной суммы с сохраненной.
* **Использование соли:** Применение случайной соли для повышения устойчивости к атакам.
* **Безопасное сравнение:** Использование `hmac.compare_digest` для предотвращения атак по времени при верификации.

## Установка

Для использования модуля Integrity Protector необходимо установить Python 3.6 или выше.

1.  Склонируйте репозиторий (если код распространяется через репозиторий) или скопируйте файл `integrity_protector.py` в свой проект.

## Использование

```python
import hashlib
import hmac
import json
import os
from typing import Dict, Tuple

class IntegrityProtector:
    """
    Класс для защиты целостности скриптов с использованием символьного пароля.
    Поддерживает HMAC-SHA256 для обеспечения целостности и аутентификации.
    """
    def __init__(self, algorithm='hmac-sha256'):
        self.algorithm = algorithm.lower()
        if self.algorithm not in ['hmac-sha256']:
            raise ValueError(f"Поддерживается только алгоритм: hmac-sha256, но был передан: {algorithm}")

    def _generate_salt(self, length=16) -> str:
        """Генерация случайной соли."""
        return os.urandom(length).hex()

    def protect_script(self, script_content: str, password: str) -> Dict:
        """
        Генерация защищенного представления скрипта с использованием HMAC-SHA256 и соли.

        Args:
            script_content: Содержимое скрипта в виде строки.
            password: Символьный пароль для защиты.

        Returns:
            Словарь, содержащий защищенную информацию: скрипт, контрольную сумму, соль и алгоритм.
        """
        salt = self._generate_salt()
        key = password.encode('utf-8')
        data = script_content.encode('utf-8') + salt.encode('utf-8')
        hmac_obj = hmac.new(key, msg=data, digestmod=hashlib.sha256)
        checksum = hmac_obj.hexdigest()
        protected_data = {
            'script': script_content,
            'checksum': checksum,
            'salt': salt,
            'algorithm': self.algorithm
        }
        return protected_data

    def save_protected_data(self, protected_data: Dict, output_file: str):
        """
        Сохранение защищенной информации в файл в формате JSON.

        Args:
            protected_data: Словарь с защищенной информацией, полученный от protect_script.
            output_file: Путь к файлу для сохранения.
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(protected_data, f, indent=4)
            print(f"Защищенная информация сохранена в: {output_file}")
        except IOError as e:
            print(f"Ошибка при сохранении в файл: {e}")

    def load_protected_data(self, input_file: str) -> Dict:
        """
        Загрузка защищенной информации из файла в формате JSON.

        Args:
            input_file: Путь к файлу для загрузки.

        Returns:
            Словарь с защищенной информацией или None в случае ошибки.
        """
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except IOError as e:
            print(f"Ошибка при загрузке из файла: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"Ошибка при декодировании JSON из файла: {e}")
            return None

    def verify_script(self, protected_data: Dict, password: str) -> bool:
        """
        Проверка целостности скрипта на основе защищенных данных и пароля.

        Args:
            protected_data: Словарь с защищенной информацией, загруженный из файла.
            password: Символьный пароль для проверки.

        Returns:
            True, если целостность скрипта подтверждена, False - в противном случае.
        """
        script = protected_data.get('script')
        stored_checksum = protected_data.get('checksum')
        salt = protected_data.get('salt')
        algorithm = protected_data.get('algorithm')

        if not all([script, stored_checksum, salt, password, algorithm]):
            print("Ошибка: Отсутствуют необходимые данные для верификации.")
            return False

        key = password.encode('utf-8')
        data = script.encode('utf-8') + salt.encode('utf-8')

        if algorithm.lower() == 'hmac-sha256':
            hmac_obj = hmac.new(key, msg=data, digestmod=hashlib.sha256)
            calculated_checksum = hmac_obj.hexdigest()
            return hmac.compare_digest(calculated_checksum, stored_checksum)
        else:
            print(f"Ошибка: Неподдерживаемый алгоритм: {algorithm}")
            return False

if __name__ == "__main__":
    # Пример использования

    protector = IntegrityProtector(algorithm='hmac-sha256')

    # Исходный скрипт
    original_script = """
    print("Hello, world!")
    import os
    print(f"Current directory: {os.getcwd()}")
    """

    # Пароль для защиты
    protection_password = "this_is_a_secret_key"

    # Защита скрипта
    protected_info = protector.protect_script(original_script, protection_password)
    print("Защищенная информация:", protected_info)

    # Сохранение защищенной информации в файл
    output_file = "protected_script.json"
    protector.save_protected_data(protected_info, output_file)

    # Загрузка защищенной информации из файла
    loaded_info = protector.load_protected_data(output_file)

    if loaded_info:
        # Попытка верификации с правильным паролем
        verification_password_correct = "this_is_a_secret_key"
        is_valid_correct = protector.verify_script(loaded_info, verification_password_correct)
        print(f"\nВерификация с правильным паролем: {'Успешно' if is_valid_correct else 'Неудачно'}")

        # Попытка верификации с неправильным паролем
        verification_password_incorrect = "wrong_password"
        is_valid_incorrect = protector.verify_script(loaded_info, verification_password_incorrect)
        print(f"Верификация с неправильным паролем: {'Успешно' if is_valid_incorrect else 'Неудачно'}")

        # Модификация скрипта после защиты (эмуляция атаки)
        modified_script = original_script.replace("Hello", "Goodbye")
        loaded_info['script'] = modified_script

        # Попытка верификации модифицированного скрипта с правильным паролем
        is_valid_modified = protector.verify_script(loaded_info, verification_password_correct)
        print(f"Верификация модифицированного скрипта: {'Успешно' if is_valid_modified else 'Неудачно'}")
```

Описание кода:

IntegrityProtector Class:

__init__(self, algorithm='hmac-sha256'): Конструктор класса. По умолчанию устанавливает алгоритм HMAC-SHA256. В текущей реализации поддерживается только HMAC-SHA256.
_generate_salt(self, length=16) -> str: Приватный метод для генерации случайной соли (последовательности случайных байт в шестнадцатеричном представлении). Соль используется для повышения безопасности.
protect_script(self, script_content: str, password: str) -> Dict: Основной метод для защиты скрипта.
Генерирует случайную соль.
Кодирует скрипт и соль в байты.
Использует библиотеку hmac с алгоритмом SHA-256 и предоставленным паролем в качестве ключа для вычисления контрольной суммы (MAC-тега).
Возвращает словарь, содержащий исходный скрипт, вычисленную контрольную сумму, использованную соль и название алгоритма.
save_protected_data(self, protected_data: Dict, output_file: str): Метод для сохранения защищенной информации (словаря) в файл в формате JSON.
load_protected_data(self, input_file: str) -> Dict: Метод для загрузки защищенной информации из файла JSON.
verify_script(self, protected_data: Dict, password: str) -> bool: Метод для проверки целостности скрипта.
Извлекает скрипт, сохраненную контрольную сумму, соль и алгоритм из protected_data.
Повторно вычисляет контрольную сумму с использованием предоставленного пароля и извлеченной соли.
Использует hmac.compare_digest для безопасного сравнения вычисленной и сохраненной контрольных сумм, предотвращая атаки по времени.
Возвращает True, если контрольные суммы совпадают (целостность подтверждена), и False в противном случае.
if __name__ == "__main__": Block (Пример использования):

Создается экземпляр класса IntegrityProtector.
Определяется исходный скрипт и пароль для защиты.
Вызывается метод protect_script для получения защищенной информации.
Защищенная информация сохраняется в файл protected_script.json.
Загружается защищенная информация из файла.
Выполняются две попытки верификации: с правильным и неправильным паролем, демонстрируя, что только правильный пароль может подтвердить целостность.
Эмулируется модификация скрипта после защиты, и выполняется еще одна попытка верификации, показывая, что изменение содержимого приводит к неудачной проверке целостности.
Как использовать этот код:

Сохраните код в файл integrity_protector.py.
Запустите скрипт из командной строки: python integrity_protector.py.
Вы увидите процесс защиты скрипта, сохранения защищенной информации в файл protected_script.json и результаты попыток верификации с правильным и неправильным паролями, а также с модифицированным скриптом.
Этот код представляет собой полноценный прототип, демонстрирующий основные принципы защиты целостности скриптов с использованием HMAC-SHA256 и символьного пароля. Для реального использования в production-среде могут потребоваться дополнительные меры безопасности, обработка ошибок и более гибкая конфигурация.

