from setuptools import setup
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README.md file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

PACKAGE_NAME = 'keepersdk'

init_vars = {}
here = path.join(here, PACKAGE_NAME)
with open(path.join(here, '__init__.py'), encoding='utf-8', mode='r') as f_init:
    for line in f_init:
        if not line.startswith('__'):
            continue
        for var in {'version', 'license', 'author'}:
            key = '__{0}__'.format(var)
            if line.startswith(key):
                init_vars[var] = line[len(key):].strip(' =\'\"\r\n')

install_requires = [
    'requests',
    'protobuf>=3.6.0',
    'cryptography'
]

setup(name=PACKAGE_NAME,
      version=init_vars['version'],
      author=init_vars.get('author') or 'Keeper Security Inc.',
      license=init_vars.get('license') or 'MIT',
      description='Keeper API SDK',
      long_description=long_description,
      long_description_content_type='text/markdown',
      author_email='ops@keepersecurity.com',
      url='https://github.com/Keeper-Security/keeper-sdk-python',
      classifiers=['Development Status :: 4 - Beta',
                   'License :: OSI Approved :: MIT License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python :: 3.4',
                   'Topic :: Security'],
      keywords='keeper security password',
      packages=[PACKAGE_NAME],
      python_requires='>=3.4',
      install_requires=install_requires
      )
