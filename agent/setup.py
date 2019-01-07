import setuptools

with open('requirements.txt') as f:
    required = f.read().splitlines()

setuptools.setup(
    name="wott-agent",
    version='0.1.0',

    author="Viktor Petersson",
    author_email="v@viktopia.io",

    description="WoTT agent",

    packages=setuptools.find_packages('src', exclude=('tests',)),
    package_dir={'': 'src'},
    include_package_data=True,
    zip_safe=False,

    install_requires=required,

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],

    entry_points={
        'console_scripts': [
            'wott-agent = agent.main:main',
        ],
    }
)
