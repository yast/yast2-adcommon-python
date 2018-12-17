#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='adcommon',
    version='1.0',
    author='David Mulder',
    author_email='dmulder@suse.com',
    description='Common code for the yast python ad modules',
    url='https://github.com/dmulder/yast2-adcommon-python',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'LICENSE :: OSI APPROVED :: GNU GENERAL PUBLIC LICENSE V3 OR LATER (GPLV3+)',
        'Operating System :: POSIX :: Linux',
    ],
)
