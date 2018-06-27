import subprocess
from os import path
from setuptools import setup
from setuptools.command.install import install


here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            subprocess.call(['/bin/sh', 'prepare_pip.sh'], cwd=here)
            subprocess.call(['python', 'prepare_pip.py'], cwd=here)
        except Exception as e:
            print(e)
            print("Error compiling openssl.")
            exit(1)
        else:
            install.run(self)

bbc_simple_requires = [
                       'pyOpenSSL>=16.2.0',
                       'jinja2>=2.8.1',
                       'requests>=2.12.4',
                       'gevent>=1.2.1',
                       'greenlet',
                       'cryptography',
                       'pytest<=3.2.*,>=3.0.5',
                       'msgpack-python',
                       'mysql-connector-python==8.0.5',
                       'dictproxyhack==1.1',
                       'fluent-logger==0.9.0',
                       'PyYAML==3.12',
                       'bson',
                       'Flask==1.0.2',
                       'Flask-Cors==3.0.4',
                       'aiohttp',
                       'aiohttp-cors',
                       'redis'
                ]

bbc_simple_packages = ['bbc_simple', 'bbc_simple.core', 'bbc_simple.app', 'bbc_simple.logger']

bbc_simple_commands = [
                       'bbc_simple/core/bbc_core.py',
                       'utils/performance_tester.py']

bbc_simple_classifiers = [
                          'Development Status :: 4 - Beta',
                          'Programming Language :: Python :: 3.5',
                          'Programming Language :: Python :: 3.6',
                          'Topic :: Software Development']

setup(
    name='bbc_simple',
    version='0.0.1.beta',
    description='Simplified Beyond Blockchain One',
    long_description=readme,
    url='https://github.com/quvox/bbc-simple',
    author='Takeshi Kubo',
    author_email='t-kubo@zettant.com',
    license='Apache License 2.0',
    classifiers=bbc_simple_classifiers,
    cmdclass={'install': MyInstall},
    packages=bbc_simple_packages,
    scripts=bbc_simple_commands,
    install_requires=bbc_simple_requires,
    zip_safe=False)

