from setuptools import find_packages, setup

requirements = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name="pirogue-admin-api",
    version="1.0.0",
    author="Christophe Andral",
    author_email="christophe@andral.fr",
    description="An API definition for managing pirogue configuration at administration level",
    url="https://github.com/PiRogueToolSuite/pirogue-admin-api",
    install_requires=requirements,
    packages=find_packages(),
    zip_safe=True,
    entry_points={},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ]
)