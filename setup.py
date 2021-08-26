import setuptools

with open('README.md', 'r') as rm:
    ld = rm.read()

setuptools.setup(
    name='Xevel',
    version='0.3.5',
    author='tsunyoku',
    author_email='tsunyoku@gmail.com',
    description='Python ASGI server',
    long_description=ld,
    long_description_content_type='text/markdown',
    url='https://github.com/tsunyoku/Xevel',
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8'
)
