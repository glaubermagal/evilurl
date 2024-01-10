import os

from setuptools import setup

setup(
    name='evilurl',
    version='0.0.8',
    packages=['src'],
    setup_requires=['wheel'],
    entry_points={
        'console_scripts': [
            'evilurl=src.evilurl:main',
        ],
    },
    author='Glauber',
    author_email='apt65@proton.me',
    description='A tool for analyzing domains for the risk of IDN homograph attacks',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/glaubermagal/evilurl',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    data_files=[
        (os.path.join(os.path.expanduser('~'), '.local', 'share', 'man', 'man1'), ['src/evilurl.1']),
    ],
)
