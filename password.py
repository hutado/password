# -*- coding: utf-8 -*-

"""
Реализация консольной утилиты генерации пароля
"""

__author__ = 'Zhuravlev Petr'

import re
import random
import string
import hashlib
import argparse

from math import log2


ALPHABET = string.ascii_letters + string.digits


class Password:
    """
    Класс генерации пароля

    Генерирует пароль заданной длины
    из любого числа ключевых слов

    Attributes:
        key: конкатенированная строка из ключевых слов
        length: длина пароля
        password: сгенерированный пароль
    """

    def __init__(self, *args, length: int) -> None:
        """
        Устанавливает все атрибуты

        Args:
            args: любое количество ключевых слов
            length: длина пароля
        """

        self.key = ''.join(args)
        self.length = length
        self.password = ''

    @staticmethod
    def get_md5(string: str) -> str:
        """
        Хэширование строки

        Args:
            string: Строка для хэширования

        Returns:
            Хэшированная строка
        """

        md5 = hashlib.md5()
        md5.update(str(string).encode())

        return md5.hexdigest()

    def encrypt(self) -> None:
        """
        Генерация пароля
        """

        self.password = self.get_md5(self.key or ''.join([random.choice(ALPHABET) for _ in range(self.length)]))[:self.length]
        new_password = ''

        # Четный символ меняется на букву, если это цифра, либо меняется на прописную
        for i, symbol in enumerate(self.password):
            if i % 2 != 0:
                if symbol.isdigit():
                    new_password += chr(ord('z') - int(symbol))
                else:
                    new_password += symbol.upper()
            else:
                new_password += symbol

        self.password = new_password


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='Password Generator',
        description='Консольная утилита для генерации пароля заданной длины из любого числа ключевых слов',
        epilog='Пароль будет всегда одинаков для одних и тех же параметров',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('keys', nargs='*', help='Ключевые слова')

    parser.add_argument(
        '-l', '--length',
        required=False,
        type=int,
        default=8,
        help='Длина пароля (default: 8)'
    )

    args = parser.parse_args()

    keys: list = args.keys
    length_: int = args.length

    password = Password(*keys, length=length_)
    password.encrypt()

    print(password.password)
