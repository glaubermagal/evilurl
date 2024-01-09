from setuptools import setup

setup(
    name='evilurl',
    version='0.0.4',
    packages=['evilurl'],
    entry_points={
        'console_scripts': [
            'evilurl=evilurl.evilurl:main',
        ],
    },
)
