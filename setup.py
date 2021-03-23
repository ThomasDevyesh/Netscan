from setuptools import setup
setup(
    name = 'Netscan',
    version = '0.1.0',
    packages = ['netscan'],
    entry_points = {
        'console_scripts': [
            'netscan = netscan.__main__:main'
        ]
    })