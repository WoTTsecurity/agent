from setuptools import setup, find_packages


setup(
    name="wott-agent",
    version='0.1.2',

    author="Viktor Petersson",
    author_email="v@viktopia.io",

    description="WoTT agent",

    packages=find_packages(exclude=('tests',)),
    include_package_data=True,

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],

    install_requires=[
        'certifi',
        'cffi',
        'chardet',
        'cryptography',
        'idna',
        'netifaces',
        'pyOpenSSL',
        'requests',
        'sh',
        'pytz'
    ],

    entry_points={
        'console_scripts': [
            'wott-agent = agent.__main__:main',
        ],
    }
)
