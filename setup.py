import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="okta-jwt-verifier",
    version="0.1.0",
    description="A subset of RFC 7519 for working with JWTs minted by Okta",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/mdwallick/okta-jwt",
    author="Mike Wallick",
    author_email="mike.wallick@okta.com",
    license="GPLv3",
    packages=["okta-jwt"],
    include_package_data=True,
    install_requires=["cryptography", "python-dotenv", "requests"],
    entry_points={
        "console_scripts": [
            "oktajwt=okta-jwt.__main__:main",
        ]
    },
)
