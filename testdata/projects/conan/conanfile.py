from conan import ConanFile

class MyPackage(ConanFile):
    name = "my_package"
    version = "1.0.0"

    requires = [
        "zlib/1.3.1",
        "openssl/3.0.9",
        "meson/1.4.1"
    ]

    def build_requirements(self):
        self.build_requires("meson/1.4.1")

    def build(self):
        pass

    def package(self):
        pass

    def package_info(self):
        pass