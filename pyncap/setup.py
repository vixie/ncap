from distutils.core import setup
from distutils.extension import Extension
from Pyrex.Distutils import build_ext
setup(
  name = "pyncap",
  ext_modules=[ 
    Extension("pyncap", ["pyncap.pyx", "wrap.c"],
              libraries = ["ncap", "pcap"])
    ],
  cmdclass = {'build_ext': build_ext}
)
