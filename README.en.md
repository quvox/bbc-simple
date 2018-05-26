Simple version of BBc-1
====
This implementation is a simpler version of BBc-1, which uses bson-formatted data structure for a transaction.
"Simple" means that this implementation, bbc-simple, omits networking, cross-ref (domain-0), secure communication and 
data replication functionality. bbc-simple depends on other frameworks for these functionality.

# Environment

* Python
    - Python 3.5.0 or later
    - pipenv is recommended
        - add ```export PIPENV_VENV_IN_PROJECT=true``` in .bash_profile

* tools for macOS by Homebrew
    ```
    brew install libtool automake python3 pipenv
    ```

* tools for Linux (Ubuntu 16.04 LTS)
    ```
    sudo apt-get install -y git tzdata openssh-server python3 python3-dev libffi-dev net-tools autoconf automake libtool libssl-dev make
    pip install pipenv
    ```


# Installation
1. Install development tools (libtool, automake)
2. Install python and pip
3. Clone this project
4. Prepare OpenSSL-based library in the root directory
    ```
    sh prepare.sh
    ```
5. Install dependencies by the following command (in the case of python 3.6)
    ```
    pipenv install
    pipenv shell
    ```
    Because Pipfile is configured for python version 3.6, use the following if your python version is not 3.6:
    ```
    pipenv install -r requirements.txt
    pipenv shell
    ``` 

