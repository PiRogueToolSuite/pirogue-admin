from setuptools import find_packages, setup

requirements = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name="pirogue-admin",
    version="1.0.0",
    author="Cyril Brulebois",
    author_email="cyril@debamax.com",
    description="Admin management for the PiRogue",
    url="https://github.com/PiRogueToolSuite/pirogue-admin",
    install_requires=requirements,
    packages=find_packages(),
    zip_safe=True,
    entry_points={
        "console_scripts": [
            "pirogue-admin = pirogue_admin.cmd.cli:main",
            "pirogue-admin-wireguard = pirogue_admin.cmd.wireguard_cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
)
