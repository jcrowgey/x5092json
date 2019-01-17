"""Python installation definition for x5092json"""
from setuptools import setup

setup(name='x5092json',
      version='1.0.2',
      description='x5092json Utility',
      author='Joshua Crowgey',
      author_email='jcrowgey@uw.edu',
      url='https://github.com/jcrowgey/x5092json',
      license='BSD',
      packages=['x5092json'],
      data_files=[('man/man1', ['doc/man1/x5092json.1'])],
      long_description=open('README.md').read(),
      long_description_content_type='text/markdown',
      python_requires='>=3.5',
      install_requires=[
          'asn1',
          'cryptography>=2.2.3',
          'pyOpenSSL'
      ],
      entry_points={
          'console_scripts':
              ['x5092json = x5092json.x509parser:main']
      },
      classifiers=[
          "Development Status :: 5 - Production/Stable",
          "Environment :: Console",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: 3.7",
      ])
