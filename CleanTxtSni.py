#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os

def main():
    # Проверка аргументов
    if len(sys.argv) != 3:
        print("Использование: python filter_txt.py <файл.txt> <sni.txt>")
        print("Пример: python filter_txt.py data.txt sni.txt")
        sys.exit(1)
    
    input_file = sys.argv[1]
    sni_file = sys.argv[2]
    
    # Проверка существования файлов
    if not os.path.exists(input_file):
        print(f"❌ Ошибка: Файл '{input_file}' не найден!")
        sys.exit(1)
    
    if not os.path.exists(sni_file):
        print(f"❌ Ошибка: Файл '{sni_file}' не найден!")
        sys.exit(1)
    
    try:
        # Чтение списка разрешенных строк из sni.txt
        with open(sni_file, 'r', encoding='utf-8') as f:
            allowed_strings = [line.strip() for line in f if line.strip()]
        
        if not allowed_strings:
            print("❌ Ошибка: Файл sni.txt пуст!")
            sys.exit(1)
        
        print(f"📋 Загружено {len(allowed_strings)} разрешенных строк из {sni_file}")
        
        # Чтение исходного файла
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        print(f"📄 Всего строк в файле: {total_lines}")
        
        # Фильтрация строк
        filtered_lines = []
        removed_lines = 0
        
        for line_num, line in enumerate(lines, 1):
            # Проверяем, содержит ли строка хотя бы одну разрешенную подстроку
            if any(allowed_str in line for allowed_str in allowed_strings):
                filtered_lines.append(line)
            else:
                removed_lines += 1
                # Для отладки можно раскомментировать:
                # print(f"  Удалена строка {line_num}: {line.strip()[:50]}...")
        
        # Запись отфильтрованных строк обратно в файл
        with open(input_file, 'w', encoding='utf-8') as f:
            f.writelines(filtered_lines)
        
        # Вывод статистики
        kept_lines = len(filtered_lines)
        print(f"✅ Операция завершена!")
        print(f"   Удалено строк: {removed_lines}")
        print(f"   Оставлено строк: {kept_lines}")
        print(f"   Процент сохраненных: {(kept_lines/total_lines*100):.1f}%")
        print(f"   Файл '{input_file}' обновлен!")
        
    except PermissionError:
        print(f"❌ Ошибка: Нет прав доступа к файлу!")
        sys.exit(1)
    except UnicodeDecodeError:
        print(f"❌ Ошибка: Проблемы с кодировкой файла. Убедитесь, что файл в UTF-8")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Неожиданная ошибка: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
