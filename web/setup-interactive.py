#!/usr/bin/env python3
import os
import sys
import platform
import subprocess
from pathlib import Path

IS_WINDOWS = platform.system() == 'Windows'

def print_banner():
    print('='*50)
    print('  PHANTOMSTRIKE v2.0 - Setup')
    print('='*50)

def get_input(prompt, default=''):
    if default:
        full = f'{prompt} [{default}]: '
    else:
        full = f'{prompt}: '
    value = input(full)
    if not value and default:
        value = default
    return value

def get_yes_no(prompt, default=True):
    suffix = ' [Y/n]: ' if default else ' [y/N]: '
    r = input(prompt + suffix).strip().lower()
    if not r:
        return default
    return r in ['y', 'yes']

def select_multiple(options):
    print('\nSelect providers (comma-separated numbers or all):')
    for i, (key, desc) in enumerate(options, 1):
        print(f'  {i}. {key}')
    r = input('Selection: ').strip().lower()
    if r == 'all':
        return [opt[0] for opt in options]
    selected = []
    for part in r.split(','):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(options):
                selected.append(options[idx][0])
        except:
            pass
    return selected

AI_PROVIDERS = [
    ('anthropic', 'Anthropic Claude'),
    ('openai', 'OpenAI GPT'),
    ('deepseek', 'DeepSeek'),
    ('glm', 'GLM-5'),
    ('together', 'Together AI'),
    ('mistral', 'Mistral AI'),
    ('groq', 'Groq'),
    ('openrouter', 'OpenRouter'),
    ('local', 'Local/Ollama'),
]

def configure_providers():
    print('\n[2/4] AI Provider Configuration')
    print('-'*40)
    print('Select AI providers (multiple for redundancy):\n')
    selected = select_multiple(AI_PROVIDERS)
    if not selected:
        print('Using default (Anthropic).')
        selected = ['anthropic']
    config = {}
    for provider in selected:
        print(f'\nConfiguring {provider.upper()}:')
        api_key = get_input(f'{provider.upper()} API Key')
        defaults = {
            'anthropic': 'claude-3-5-sonnet-20241022',
            'openai': 'gpt-4o',
            'deepseek': 'deepseek-chat',
            'glm': 'glm-5',
            'together': 'meta-llama/Llama-3.1-70B',
            'mistral': 'mistral-large-latest',
            'groq': 'llama-3.1-70b-versatile',
            'openrouter': 'anthropic/claude-3.5-sonnet',
            'local': 'llama3.1:70b',
        }
        model = get_input('Model', defaults.get(provider, ''))
        config[provider] = {'api_key': api_key, 'model': model}
    return config

def configure_db():
    print('\n[3/4] Database Configuration')
    print('-'*40)
    print('1. SQLite (embedded)')
    print('2. PostgreSQL')
    c = input('Select [1-2, default=1]: ').strip() or '1'
    if c == '1':
        return {'type': 'sqlite', 'path': './data/phantomstrike.db'}
    return {'type': 'postgres', 'host': 'localhost', 'port': '5432',
            'user': 'phantomstrike', 'password': 'phantomstrike_secret',
            'dbname': 'phantomstrike'}

def generate_env(config):
    env = f'''# PhantomStrike Configuration
APP_NAME=PhantomStrike
APP_VERSION=2.0.0
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
JWT_SECRET={os.urandom(32).hex()}
API_KEY={os.urandom(16).hex()}
DB_TYPE={config["database"]["type"]}
'''
    if config['database']['type'] == 'sqlite':
        env += f'DB_PATH={config["database"]["path"]}\n'
    else:
        env += f'''DB_HOST={config['database']['host']}
DB_PORT={config['database']['port']}
DB_USER={config['database']['user']}
DB_PASSWORD={config['database']['password']}
DB_NAME={config['database']['dbname']}
'''
    env += f'PROVIDERS={",".join(config["providers"].keys())}\n\n'
    for name, settings in config['providers'].items():
        prefix = name.upper()
        env += f'{prefix}_API_KEY={settings["api_key"]}\n'
        if settings.get('model'):
            env += f'{prefix}_MODEL={settings["model"]}\n'
    return env

def save_files(config):
    print('\n[4/4] Generating Configuration Files')
    print('-'*40)
    root = Path(__file__).parent.absolute()
    (root / 'data').mkdir(exist_ok=True)
    with open(root / '.env', 'w') as f:
        f.write(generate_env(config))
    print('Created .env')

def main():
    print_banner()
    print('\n[1/4] Checking Dependencies')
    print('-'*40)
    if sys.version_info < (3, 8):
        print('Error: Python 3.8+ required.')
        sys.exit(1)
    print(f'Python {sys.version.split()[0]} OK')
    check = 'where' if IS_WINDOWS else 'which'
    try:
        subprocess.run([check, 'docker'], capture_output=True)
        print('Docker available')
    except:
        pass
    config = {
        'providers': configure_providers(),
        'database': configure_db(),
    }
    save_files(config)
    print('\n' + '='*50)
    print('Setup complete!')
    print('Run: python start.py')
    print('='*50)
    if get_yes_no('Start now?'):
        os.execv(sys.executable, [sys.executable, 'start.py'])

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nSetup cancelled.')
