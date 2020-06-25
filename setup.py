import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="dash-keycloak",
    version="0.0.18rc1",
    description="Flask extension providing Keycloak integration via the python-keycloak package",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/",
    author="Emil Haldrup Eriksen",
    author_email="emil.h.eriksen@gmail.com",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
    ],
    packages=["flask_keycloak", "flask_keycloak.examples"],
    include_package_data=True,
    install_requires=["flask", "python-keycloak"],
    # entry_points={
    #     "console_scripts": [
    #         "realpython=reader.__main__:main",
    #     ]
    # },
)
