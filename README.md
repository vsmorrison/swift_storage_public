# Тесты swift

## Описание

Проект предствляет собой частичное покрытие тестами API https://docs.openstack.org/api-ref/object-store/, 
в реализации использовалась Keystone авторизация.

## Фреймворк

Для тестирования используется фреймворк pytest

```pip install pytest```

## Тесты и их настройка 

Значения урлов, логинов, паролей должны содержаться в файлах ```pytest_stage.ini``` и ```pytest_test.ini``` (stage/test окружения)
Формат для ```.ini``` файлов:

```
pythonpath = .
PROJECT_ID=PROJECT_ID
SWIFT_API_URL=
KEYSTONE_URL=
USERID=USERID
PASSWORD=PASSWORD
```

## Запуск тестов

Для запуска тестов с разными конфигами необходимо добавить ключ ```-c``` и имя ini-файла:
```pytest -c pytest_stage.ini test_container.py``` 
 
