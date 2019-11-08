from setuptools import find_packages
from setuptools import setup

from simple_detect_secrets import VERSION


setup(
    name='simple_detect_secrets',
    packages=find_packages(exclude=(['test*', 'tmp*'])),
    version=VERSION,
    description='Tool for detecting secrets in the codebase',
    long_description=(
        'Check out simple-detect-secrets on `GitHub <https://github.com/malthejorgensen/simple-detect-secrets>`_!'
    ),
    license='Copyright Yelp, Inc. 2018',
    author=u'Malthe Jørgensen',
    author_email='malthe.jorgensen@gmail.com',
    url='https://github.com/malthejorgensen/simple-detect-secrets',
    download_url='https://github.com/malthejorgensen/simple-detect-secrets/archive/{}.tar.gz'.format(
        VERSION
    ),
    keywords=['secret-management', 'pre-commit', 'security', 'entropy-checks'],
    install_requires=['pyyaml', 'requests'],
    extras_require={
        ':python_version=="2.7"': ['configparser', 'enum34', 'future', 'functools32'],
        'word_list': ['pyahocorasick'],
    },
    entry_points={
        'console_scripts': ['simple-detect-secrets = simple_detect_secrets.main:main']
    },
    classifiers=[
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Intended Audience :: Developers',
        'Topic :: Software Development',
        'Topic :: Utilities',
        'Environment :: Console',
        'Operating System :: OS Independent',
        'Development Status :: 5 - Production/Stable',
    ],
)
