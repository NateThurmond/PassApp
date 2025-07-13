# Pass App

Provides secure browser access to hosted .kdbx file for remote password access

## Description

While 2FA and other recent advances have made password management a lot easier, there are still some sites that require you to know your password. Rather than reinventing the wheel, this app provides secure browser access to those passwords that have may have been saved previously in keepass format.

### Dependencies

-   Python3
-   .KDBX Database file
-   pyenv (optional, for managing Python versions and virtual environments)

### Setup

1. **Install pyenv and pyenv-virtualenv** (if not already installed):
   Follow the instructions from the [pyenv](https://github.com/pyenv/pyenv#installation) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv#installation) repositories to install these tools.

2. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/pyEnphaseGraph.git
    cd pyEnphaseGraph
    ```
3. **Set up the virtual environment**:
    ```sh
    pyenv install 3.10.0  # Install Python 3.10.0 if not already installed
    pyenv virtualenv 3.10.0 passApp  # Create a virtual environment named 'passApp'
    pyenv activate passApp  # Activate the virtual environment
    ```
4. **Install the dependencies**:
    ```sh
    pip install -r requirements.txt  # Install the required packages
    ```
5. **Run the script:**
    ```
    python passApp.py
    ```

Inspiration, code snippets, etc.

-   [KeePass XC](https://keepassxc.org/)
-   [Keeper](https://www.keepersecurity.com/)
