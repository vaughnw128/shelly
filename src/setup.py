from cx_Freeze import setup,Executable

includefiles = ['./lib/shlib.py']
includes = []
excludes = ['']

packages = []
with open('requirements.txt', 'r') as f:
    for line in f.readlines():
        packages.append(line.split('==')[0].strip())

setup(
    name = 'implant',
    version = '0.1',
    description = 'Shelly implant',
    author = 'apicius',
    author_email = '',
    options = {'build_exe': {'includes':includes,'excludes':excludes,'packages':packages,'include_files':includefiles}}, 
    executables = [Executable('implant.py')]
)