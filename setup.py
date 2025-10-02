from setuptools import setup, find_packages

setup(
    name="logsnoop",
    version="1.0.0",
    description="Python log parser with plugin architecture",
    long_description="A flexible log parser that can analyze different types of logs through a plugin system. Supports SSH, FTP, HTTP logs and stores results in a flat file database.",
    author="LogSnoop Team",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        # No external dependencies required for base functionality
    ],
    entry_points={
        'console_scripts': [
            'logsnoop=cli:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
