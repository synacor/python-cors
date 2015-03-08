from setuptools import setup, find_packages

setup(
    name="cors",
    version="0.3.0",
    description="Utilities for creating CORS-enabled HTTP interfaces",
    author="Nick Coutsos",
    author_email="ncoutsos@synacor.com",
    packages=find_packages(exclude=["*tests*"]),
)
