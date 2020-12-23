import setuptools

from dangee import __version__

with open("README.md") as fh:
    long_description = fh.read()

setuptools.setup(
    name="Dangee",  # Replace with your own username
    version=__version__,
    author="JunWei Song",
    author_email="sungboss2004@gmail.com",
    description="Dangee",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/quark-engine/Dangee",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=[
        "quark-engine",
    ],
)
