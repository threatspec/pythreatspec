try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'pythreatspec',
    'author': 'Christopher A. Wood',
    'url': 'https://github.com/threatspec/pythreatspec.',
    'download_url': '#',
    'author_email': '#',
    'version': '0.1',
    'install_requires': ['nose'],
    'setup_requires': ['flake8'],
    'packages': ['pythreatspec'],
    'scripts': [],
    'name': 'pythreatspec'
}

setup(**config)
