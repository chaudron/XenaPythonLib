from setuptools import setup

setup(name='xenalib-python',
      version_format='{tag}.dev{commitcount}+{gitsha}',
      setup_requires=['setuptools-git-version'],
      description='Python Interface To Xena Traffic Generator',
      url='http://github.com/fleitner/XenaPythonLib',
      author='Flavio Leitner',
      author_email='fbl@redhat.com',
      license='MIT',
      packages=['xenalib'],
      zip_safe=False)

