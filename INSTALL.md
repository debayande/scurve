# Instructions for installation

These instructions have been tested on a freshly-installed copy of Ubuntu
17.04. Instructions for macOS will be added soon.

## Prerequisites

The sections that follow assume that the following packages are installed and
available on your system:

* [`pyenv`](https://github.com/pyenv/pyenv)
* [`pyenv-virtualenv`](https://github.com/pyenv/pyenv-virtualenv)
* Python `2.7.x` on `pyenv` (replace `x` with the appropriate revision number)

## Set up the development environment and resolve dependencies

To set up the development environment, change to a folder of your choice and
issue these commands:

```
$ sudo apt-get install libpango1.0-0 libcairo2 libpq-dev
$ pyenv virtualenv 2.7.x dexvis
$ pyenv activate dexvis
$ git clone https://github.com/debayande/scurve.git
$ cd scurve
$ pip install .
$ pip install cairocffi Pillow
```

`dexvis` should now be ready for use.

## Verify the installation

To verify that the installation was successful, issue:

`./dexvis`

If everything went smoothly, you should now be greeted by a help message.