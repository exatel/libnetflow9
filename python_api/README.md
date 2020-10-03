# Python API for libnetflow9

## Usage

1. Build library as stated in main README.md file.
   By default the libnetflow9.so file will be created.

2. By default python lib looks for libnetflow9.so file in build directory.
   In order to use your own path set LD_LIBRARY_PATH variable.

3. Prepare your virtual environment

    ```console
    pip3 install virtualenv
    python3 -m venv ENV
    source ENV/bin/activate
    ```

4. Using pip install requirements

    ```console
    pip3 install -r requirements.txt
    ```

5. Run example with default configuration or with arguments

    ```console
    python3 example.py
    ```

    ```console
    python3 example.py --help
    ```
