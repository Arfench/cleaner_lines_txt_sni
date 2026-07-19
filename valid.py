#!/usr/bin/env python3
"""
Скрипт для валидации и очистки VLESS конфигураций.
Поддерживает форматы: vless:// ссылки, JSON подписки Xray, Sing-Box.
"""

import re
import json
import base64
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Optional, Tuple
import sys


class VLESSValidator:
    # Известные транспортные протоколы Xray
    VALID_TRANSPORTS = {
        'tcp', 'ws', 'httpupgrade', 'grpc', 'http', 'h2', 
        'quic', 'kcp', 'xhttp', 'splithttp'
    }
    
    # Известные flow для VLESS REALITY
    VALID_FLOWS = {
        '', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'
    }
    
    # Известные security методы
    VALID_SECURITY = {
        'none', 'tls', 'reality', 'xtls'
    }
    
    def __init__(self, strict: bool = True):
        self.strict = strict
        self.errors = []
    
    @staticmethod
    def _get_str(value) -> str:
        """Безопасное получение строки из значения (может быть список)"""
        if isinstance(value, list):
            return value[0] if value else ''
        return str(value) if value is not None else ''
        
    def validate_host(self, host: str) -> bool:
        """Проверка валидности хоста/IP"""
        # Безопасное приведение к строке
        host = self._get_str(host)
        
        if not host or host.isspace():
            return False
            
        # Проверяем, не содержит ли хост явно мусорные паттерны
        garbage_patterns = [
            r'@', r'telegram', r'BIA_', r'VPN', r'proxy', r'server',
            r'Join', r'entry', r'free', r'config', r'channel',
            r'vpnserver', r'MARAMBASHI', r'External_Net', r'V2WRAY',
            r'PLANB', r'YamYam', r'VPNine'
        ]
        
        host_lower = host.lower()
        for pattern in garbage_patterns:
            if re.search(pattern, host_lower):
                return False
        
        # Проверка на IP адрес
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        
        # Проверка на домен (RFC 1035)
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(hostname_pattern, host):
            return False
            
        # Проверяем, что хост не слишком длинный
        if len(host) > 253:
            return False
            
        # Проверяем каждый сегмент
        for label in host.split('.'):
            if len(label) > 63:
                return False
                
        return True
    
    def validate_sni(self, sni: str) -> bool:
        """Проверка SNI"""
        sni = self._get_str(sni)
        if not sni:
            return True  # SNI может быть пустым для некоторых конфигов
        return self.validate_host(sni)
    
    def validate_uuid(self, uuid: str) -> bool:
        """Проверка UUID"""
        uuid = self._get_str(uuid)
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        return bool(re.match(uuid_pattern, uuid.lower()))
    
    def validate_spiderx(self, spiderx: str) -> bool:
        """Проверка spiderX (путь в REALITY)"""
        spiderx = self._get_str(spiderx)
        if not spiderx:
            return True
        
        # Проверяем на множественное кодирование (более 2 раз)
        if spiderx.count('%25') > 2:
            return False
            
        # Путь должен начинаться с /
        if not spiderx.startswith('/') and not spiderx.startswith('%2F') and not spiderx.startswith('%252F'):
            return False
            
        # Проверяем на допустимые символы в пути
        if not re.match(r'^[/%a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=]*$', spiderx):
            return False
            
        return True
    
    def validate_short_id(self, short_id: str) -> bool:
        """Проверка shortId для REALITY"""
        short_id = self._get_str(short_id)
        if not short_id:
            return True
            
        # ShortId должен быть шестнадцатеричной строкой
        hex_pattern = r'^[0-9a-fA-F]*$'
        if not re.match(hex_pattern, short_id):
            return False
            
        # Максимальная длина shortId - 16 символов (8 байт)
        if len(short_id) > 16:
            return False
            
        return True
    
    def parse_vless_url(self, url: str) -> Optional[Dict]:
        """Парсинг vless:// URL"""
        try:
            if not url.startswith('vless://'):
                return None
            
            # Удаляем префикс
            parsed = urlparse(url)
            
            # UUID и хост
            uuid = parsed.username or ''
            host = parsed.hostname or ''
            port = parsed.port or 443
            
            # Парсим query параметры
            params = {}
            for k, v in parse_qs(parsed.query).items():
                params[k] = v[0] if len(v) == 1 else v
            
            config = {
                'protocol': 'vless',
                'uuid': uuid,
                'address': host,
                'port': int(port),
                'params': params,
                'raw': url
            }
            
            # Добавляем fragment если есть
            if parsed.fragment:
                config['ps'] = unquote(parsed.fragment)
            
            return config
            
        except Exception as e:
            return None
    
    def validate_config(self, config: Dict) -> Tuple[bool, List[str]]:
        """Валидация VLESS конфигурации"""
        errors = []
        
        # Проверка обязательных полей
        if not config:
            errors.append("Empty config")
            return False, errors
        
        # Валидация хоста
        host = self._get_str(config.get('address', ''))
        if not self.validate_host(host):
            errors.append(f"Invalid host: {host}")
        
        # Валидация UUID
        uuid = self._get_str(config.get('uuid', ''))
        if not self.validate_uuid(uuid):
            errors.append(f"Invalid UUID: {uuid}")
        
        # Валидация порта
        port = config.get('port', 0)
        try:
            port = int(port)
        except (ValueError, TypeError):
            errors.append(f"Invalid port: {port}")
            port = 0
        
        if not isinstance(port, int) or port < 1 or port > 65535:
            errors.append(f"Invalid port: {port}")
        
        # Проверка параметров
        params = config.get('params', {})
        
        # Проверка transport
        transport = self._get_str(params.get('type', 'tcp'))
        if transport not in self.VALID_TRANSPORTS:
            errors.append(f"Invalid transport: {transport}")
        
        # Проверка security
        security = self._get_str(params.get('security', 'none'))
        if security not in self.VALID_SECURITY:
            errors.append(f"Invalid security: {security}")
        
        # Специфичные проверки для REALITY
        if security == 'reality':
            # spiderX
            spiderx = self._get_str(params.get('spiderX', ''))
            if not self.validate_spiderx(spiderx):
                errors.append(f"Invalid spiderX: {spiderx}")
            
            # shortId
            short_id = self._get_str(params.get('shortId', ''))
            if not self.validate_short_id(short_id):
                errors.append(f"Invalid shortId: {short_id}")
            
            # Проверка наличия pbk
            if 'pbk' not in params or not self._get_str(params.get('pbk', '')):
                errors.append("Missing pbk in REALITY config")
        
        # Проверка flow
        flow = self._get_str(params.get('flow', ''))
        if flow and flow not in self.VALID_FLOWS:
            errors.append(f"Invalid flow: {flow}")
        
        # Проверка SNI если есть
        sni = self._get_str(params.get('sni', ''))
        if sni and not self.validate_sni(sni):
            errors.append(f"Invalid SNI: {sni}")
        
        # Проверки на мусорные параметры в ключах
        garbage_patterns = [
            r'telegram', r'@', r'vpn', r'proxy', r'free',
            r'channel', r'config', r'server'
        ]
        
        for key, value in params.items():
            value_str = self._get_str(value)
            value_lower = value_str.lower()
            key_lower = key.lower()
            
            # Пропускаем легитимные поля
            if key_lower in {'sni', 'spiderx', 'pbk', 'sid', 'fp', 'type', 'security', 
                           'flow', 'path', 'host', 'alpn', 'mode', 'serviceName'}:
                continue
                
            for pattern in garbage_patterns:
                if re.search(pattern, key_lower) or re.search(pattern, value_lower):
                    errors.append(f"Garbage parameter: {key}={value_str}")
                    break
        
        return len(errors) == 0, errors
    
    def clean_configs(self, urls: List[str]) -> Tuple[List[str], List[Dict]]:
        """Очистка списка VLESS URL"""
        valid_urls = []
        invalid_configs = []
        
        for url in urls:
            url = url.strip()
            if not url or not url.startswith('vless://'):
                continue
            
            config = self.parse_vless_url(url)
            if not config:
                invalid_configs.append({
                    'url': url[:100] + '...' if len(url) > 100 else url,
                    'errors': ['Failed to parse URL']
                })
                continue
            
            is_valid, errors = self.validate_config(config)
            
            if is_valid:
                valid_urls.append(url)
            else:
                invalid_configs.append({
                    'url': url[:100] + '...' if len(url) > 100 else url,
                    'config': config,
                    'errors': errors
                })
        
        return valid_urls, invalid_configs
    
    def decode_subscription(self, data: str) -> List[str]:
        """Декодирование подписки из base64"""
        urls = []
        
        # Пробуем декодировать как base64
        try:
            # Добавляем padding если нужно
            padded = data + '=' * (-len(data) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='ignore')
            
            # Разделяем по строкам
            lines = decoded.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('vless://'):
                    urls.append(line)
        except Exception:
            pass
        
        # Если base64 не сработал - пробуем построчно
        if not urls:
            lines = data.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('vless://'):
                    urls.append(line)
        
        return urls


def process_file(input_file: str, output_file: str, verbose: bool = True):
    """Обработка файла с VLESS конфигурациями"""
    validator = VLESSValidator()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Декодируем подписку
    urls = validator.decode_subscription(content)
    
    if verbose:
        print(f"Found {len(urls)} VLESS configurations")
    
    # Очищаем конфигурации
    valid_urls, invalid_configs = validator.clean_configs(urls)
    
    if verbose:
        print(f"Valid: {len(valid_urls)}")
        print(f"Invalid: {len(invalid_configs)}")
        
        if invalid_configs:
            print("\nFirst 5 invalid configurations:")
            for idx, invalid in enumerate(invalid_configs[:5], 1):
                print(f"\n{idx}. URL: {invalid['url']}")
                print(f"   Errors:")
                for error in invalid['errors']:
                    print(f"   - {error}")
    
    # Сохраняем валидные конфигурации
    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in valid_urls:
                f.write(url + '\n')
        
        if verbose:
            print(f"\nValid configurations saved to: {output_file}")
    
    # Сохраняем отчет об ошибках
    if invalid_configs and output_file:
        report_file = output_file.replace('.txt', '_errors.txt')
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(f"Total invalid: {len(invalid_configs)}\n")
            f.write("=" * 80 + "\n\n")
            for idx, invalid in enumerate(invalid_configs, 1):
                f.write(f"{idx}. URL: {invalid['url']}\n")
                f.write(f"   Errors:\n")
                for error in invalid['errors']:
                    f.write(f"   - {error}\n")
                f.write("\n")
        
        if verbose:
            print(f"Error report saved to: {report_file}")
    
    return valid_urls, invalid_configs


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='VLESS Configuration Validator and Cleaner')
    parser.add_argument('input', help='Input file with VLESS configurations')
    parser.add_argument('-o', '--output', help='Output file for valid configurations')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode')
    
    args = parser.parse_args()
    
    try:
        process_file(args.input, args.output, not args.quiet)
    except FileNotFoundError:
        print(f"Error: File '{args.input}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
