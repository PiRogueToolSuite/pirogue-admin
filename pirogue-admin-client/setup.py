from setuptools import find_packages, setup

requirements = [i.strip() for i in open("requirements.txt").readlines()]

setup(
    name="pirogue-admin-client",
    version="1.0.0",
    author="Christophe Andral",
    author_email="christophe@andral.fr",
    description="Admin management client for the PiRogue",
    url="https://github.com/PiRogueToolSuite/pirogue-admin-client",
    install_requires=requirements,
    packages=find_packages(),
    zip_safe=True,
    entry_points={
        "console_scripts": [
            "pirogue-admin-client = pirogue_admin_client.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPL-3.0 License",
        "Operating System :: OS Independent",
    ],
)
